package io.mosip.esignet.saotome.integration.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.esignet.api.dto.*;
import io.mosip.esignet.api.exception.KycAuthException;
import io.mosip.esignet.api.exception.KycExchangeException;
import io.mosip.esignet.api.exception.SendOtpException;
import io.mosip.esignet.api.spi.Authenticator;
import io.mosip.esignet.saotome.integration.entity.KycAuth;
import io.mosip.esignet.saotome.integration.repository.KycAuthRepository;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import javax.annotation.PostConstruct;
import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;

@ConditionalOnProperty(value = "mosip.esignet.integration.authenticator", havingValue = "SaoTomeCitizensAuthenticationService")
@Component
@Slf4j
public class SaoTomeCitizensAuthenticationService implements Authenticator {

    @Value("${mosip.esignet.authenticator.saotome.send-otp-url}")
    private String otpSendUrl;

    @Value("${mosip.esignet.authenticator.saotome.verify-otp-url}")
    private String otpVerifyUrl;

    @Value("${mosip.esignet.authenticator.saotome.citizen-details-url}")
    private String citizenDetailsUrl;

    @Value("${mosip.esignet.mock.authenticator.ida.otp-channels}")
    private List<String> supportedOtpChannels;

    @Value("${mosip.esignet.authenticator.saotome.encrypt-kyc}")
    private boolean encryptKyc;

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private KycAuthRepository kycAuthRepository;

    @PostConstruct
    public void initialize() {
        log.info("Initialized Credissuer Authenticator for OTP based authentication.");
    }

    @Validated
    @Override
    public KycAuthResult doKycAuth(@NotBlank String relyingPartyId, @NotBlank String clientId,
                                   @NotNull @Valid KycAuthDto kycAuthDto) throws KycAuthException {

        log.info("Started OTP kyc-auth request with transactionId : {} && clientId : {}",
                kycAuthDto.getTransactionId(), clientId);
        try {
            if (kycAuthDto.getChallengeList() == null || kycAuthDto.getChallengeList().isEmpty()) {
                throw new KycAuthException("invalid_challenge_format");
            }
            AuthChallenge authChallenge = kycAuthDto.getChallengeList().get(0);
            if ("OTP".equals(authChallenge.getAuthFactorType())) {
                return validateOtpAuth(kycAuthDto, authChallenge);
            }
            throw new KycAuthException("unsupported_auth_factor");

        } catch (KycAuthException e) {
            throw e;
        } catch (Exception e) {
            log.error("KYC-auth failed with transactionId : {} && clientId : {}", kycAuthDto.getTransactionId(),
                    clientId, e);
            throw new KycAuthException("AUTH_FAILED");
        }
    }

    @Override
    public KycExchangeResult doKycExchange(String relyingPartyId, String clientId, KycExchangeDto request)
            throws KycExchangeException {
        log.info("KYC Exchange started for transactionId: {}", request.getTransactionId());

        Optional<KycAuth> optionalKycAuth = kycAuthRepository.findById(request.getKycToken());
        if (optionalKycAuth.isEmpty()) {
            throw new KycExchangeException("Invalid KYC Token.");
        }

        KycAuth kycAuth = optionalKycAuth.get();

        if (!Objects.equals(kycAuth.getTransactionId(), request.getTransactionId()) ||
            !Objects.equals(kycAuth.getIndividualId(), request.getIndividualId()) ||
            kycAuth.getValidity() != KycAuth.VALIDITY_ACTIVE) {

            throw new KycExchangeException("Invalid or expired KYC record.");
        }

        LocalDateTime requestTime = LocalDateTime.now();
        long seconds = kycAuth.getResponseTime().until(requestTime, ChronoUnit.SECONDS);
        if (seconds < 0 || seconds > 300) { // 5 mins
            kycAuth.setValidity(KycAuth.VALIDITY_EXPIRED);
            kycAuthRepository.save(kycAuth);
            throw new KycExchangeException("KYC session expired.");
        }

        try {
            Map<String, Object> kyc = new HashMap<>();
            kyc.put("sub", kycAuth.getPartnerSpecificUserToken());

            String signedKyc = signKyc(kyc);
            String finalKyc = encryptKyc ? getJWE(relyingPartyId, signedKyc) : signedKyc;

            kycAuth.setValidity(KycAuth.VALIDITY_USED);
            kycAuthRepository.save(kycAuth);

            KycExchangeResult response = new KycExchangeResult();
            response.setEncryptedKyc(finalKyc);
            return response;
        } catch (Exception e) {
            log.error("Error building KYC data", e);
            throw new KycExchangeException("KYC_EXCHANGE_FAILED");
        }
    }

    private String getJWE(String relyingPartyId, String signedData) {
        // Placeholder: Replace with real JWE encryption logic
        return signedData; // No-op if encryption not implemented
    }

    private String signKyc(Map<String, Object> kycData) throws JsonProcessingException {
        return objectMapper.writeValueAsString(kycData);
    }

    @Override
    public SendOtpResult sendOtp(String relyingPartyId, String clientId, SendOtpDto sendOtpDto)
            throws SendOtpException {
        List<String> requestedChannels = sendOtpDto.getOtpChannels();
        if (requestedChannels == null || requestedChannels.isEmpty()) {
            log.error("OTP request failed for clientId: {}. Reason: Channel list is null or empty.", clientId);
            throw new SendOtpException(io.mosip.esignet.core.constants.ErrorConstants.INVALID_OTP_CHANNEL);
        }
        log.debug("Client '{}' requested OTP via channels: {}", clientId, requestedChannels);

        String channelToSend = requestedChannels.stream()
                .filter(this::isSupportedOtpChannel)
                .findFirst()
                .orElseThrow(() -> new SendOtpException(io.mosip.esignet.core.constants.ErrorConstants.INVALID_OTP_CHANNEL));


        try {
            String nationalId = sendOtpDto.getIndividualId();
            String phoneNumber = getPhoneNumber(nationalId);

            if (phoneNumber == null) {
                throw new SendOtpException("PHONE_NUMBER_NOT_FOUND");
            }

            /* --------- Build request body --------- */
            Map<String, Object> requestBody = new HashMap<>();
            requestBody.put("national_id", nationalId);
            requestBody.put("phone_number", phoneNumber);
            requestBody.put("channel", channelToSend);

            String requestJson = objectMapper.writeValueAsString(requestBody);

            /* --------- Headers --------- */
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<String> entity = new HttpEntity<>(requestJson, headers);

            ResponseEntity<Map<String, Object>> responseEntity =
                    restTemplate.exchange(
                            otpSendUrl,
                            HttpMethod.POST,
                            entity,
                            new ParameterizedTypeReference<>() {});

            if (responseEntity.getStatusCode().is2xxSuccessful()) {
                SendOtpResult result = new SendOtpResult();
                result.setTransactionId(sendOtpDto.getTransactionId());
                return result;
            }

            throw new SendOtpException(
                    io.mosip.esignet.api.util.ErrorConstants.SEND_OTP_FAILED);

        } catch (Exception e) {
            throw new SendOtpException(
                    io.mosip.esignet.api.util.ErrorConstants.SEND_OTP_FAILED);
        }
    }
    private String getPhoneNumber(String nationalId) {
        try {
            // Call citizen details API to fetch registered mobile number
            ResponseEntity<Map<String, Object>> response =
                    restTemplate.exchange(
                            citizenDetailsUrl + nationalId + "/",
                            HttpMethod.GET,
                            null,
                            new ParameterizedTypeReference<>() {});

            // Return null if API does not respond with success
            if (!response.getStatusCode().is2xxSuccessful()) {
                log.warn("Citizen details API returned non-success status: {}", response.getStatusCode());
                return null;
            }

            Map<String, Object> body = response.getBody();

            // Extract mobile number if present
            if (body != null && body.containsKey("mobile_number")) {
                return String.valueOf(body.get("mobile_number"));
            }

            // Mobile number not available in response
            return null;

        } catch (HttpClientErrorException | HttpServerErrorException e) {
            // Handle HTTP errors gracefully and allow caller to decide next steps
            log.error("Failed to fetch citizen details. Status: {}", e.getStatusCode());
            return null;
        }
    }

    @Override
    public boolean isSupportedOtpChannel(String channel) {
        return supportedOtpChannels != null && supportedOtpChannels.contains(channel);
    }

    @Override
    public List<KycSigningCertificateData> getAllKycSigningCertificates() {
        return new ArrayList<>();
    }

    private KycAuthResult validateOtpAuth(KycAuthDto kycAuthDto, AuthChallenge authChallenge)
        throws KycAuthException {

        String nationalId = kycAuthDto.getIndividualId();
        String transactionId = kycAuthDto.getTransactionId();
        String otp = authChallenge.getChallenge();
        try {
            String phoneNumber = getPhoneNumber(nationalId);
            if (phoneNumber == null) {
                throw new KycAuthException("PHONE_NUMBER_NOT_FOUND");
            }

            /* --------- Build request body --------- */
            OtpVerifyRequestDto requestDto =
                    new OtpVerifyRequestDto(nationalId, phoneNumber, otp);

            String requestJson = objectMapper.writeValueAsString(requestDto);

            /* --------- Headers --------- */
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<String> entity = new HttpEntity<>(requestJson, headers);

            ResponseEntity<Map<String, Object>> responseEntity =
                    restTemplate.exchange(
                            otpVerifyUrl,
                            HttpMethod.POST,
                            entity,
                            new ParameterizedTypeReference<>() {});

            if (!responseEntity.getStatusCode().is2xxSuccessful()
                    || responseEntity.getBody() == null) {
                throw new KycAuthException("AUTH_FAILED");
            }

            /* --------- Parse response --------- */
            Map<String, Object> body = responseEntity.getBody();

            boolean verified = false;
            if (body != null) {
                Object dataObj = body.get("data");
                if (dataObj instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> data = (Map<String, Object>) dataObj;
                    verified = Boolean.TRUE.equals(data.get("verified"));
                }
            }

            if (!verified) {
                log.warn("OTP verification failed for transactionId: {}", transactionId);
                throw new KycAuthException("AUTH_FAILED");
            }

            /* --------- Success handling --------- */
            log.info("OTP verified successfully for transactionId: {}", transactionId);

            KycAuth kycAuth = new KycAuth();
            kycAuth.setKycToken(nationalId);
            kycAuth.setIndividualId(nationalId);
            kycAuth.setPartnerSpecificUserToken(nationalId);
            kycAuth.setTransactionId(transactionId);
            kycAuth.setResponseTime(LocalDateTime.now());
            kycAuth.setValidity(KycAuth.VALIDITY_ACTIVE);

            kycAuthRepository.save(kycAuth);

            KycAuthResult result = new KycAuthResult();
            result.setKycToken(nationalId);
            result.setPartnerSpecificUserToken(nationalId);

            return result;

        } catch (HttpClientErrorException e) {
            log.error("HTTP error during OTP verification. Status: {}", e.getStatusCode(), e);
            throw new KycAuthException("AUTH_FAILED");
        } catch (Exception e) {
            log.error("Exception during OTP verification for transactionId: {}", transactionId, e);
            throw new KycAuthException("AUTH_FAILED");
        }
    }


    // --- DTO Inner classes for OTP ---
    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    private static class OtpRequestDto {
        private String national_id;
        private String phone_number;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    private static class OtpVerifyRequestDto {
        private String national_id;
        private String phone_number;
        private String otp;
    }
}

