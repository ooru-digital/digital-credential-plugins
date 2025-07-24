package io.mosip.esignet.credissuer.integration.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.esignet.api.dto.*;
import io.mosip.esignet.api.exception.KycAuthException;
import io.mosip.esignet.api.exception.KycExchangeException;
import io.mosip.esignet.api.exception.SendOtpException;
import io.mosip.esignet.api.spi.Authenticator;
import io.mosip.esignet.api.dto.SendOtpDto;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import javax.annotation.PostConstruct;
import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.util.*;


@ConditionalOnProperty(value = "mosip.esignet.integration.authenticator", havingValue = "CredissuerAuthenticationService")
@Component
@Slf4j
public class CredissuerAuthenticationService implements Authenticator {

    // OTP Configuration
    @Value("${mosip.esignet.authenticator.credissuer.send-otp-url}")
    private String otpSendUrl;

    @Value("${mosip.esignet.authenticator.credissuer.verify-otp-url}")
    private String otpVerifyUrl;

    @Value("${mosip.esignet.mock.authenticator.ida.otp-channels}")
    private List<String> supportedOtpChannels;

    @Value("${mosip.esignet.authenticator.credissuer.bearer-token}")
    private String credIssuerBearerToken;

    ArrayList<String> trnHash = new ArrayList<>();

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private ObjectMapper objectMapper;


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
                log.info(">>>>>>>>>>>>>>>:",kycAuthDto.getChallengeList());
                log.info(">>>>>>>>>>>>>>>:ssdd",kycAuthDto.getChallengeList().isEmpty());
                throw new KycAuthException("invalid_challenge_format");
            }
            AuthChallenge authChallenge = kycAuthDto.getChallengeList().get(0);
            log.info(">>>>>>>>>>>>>>>auth",authChallenge);
            if (Objects.equals(authChallenge.getAuthFactorType(), "OTP")) {
                log.info(">>>>>>>>>>>>>>>authChallenge.getAuthFactorType():",authChallenge.getAuthFactorType());
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
    public KycExchangeResult doKycExchange(String relyingPartyId, String clientId, KycExchangeDto kycExchangeDto)
            throws KycExchangeException {
        log.info("kycExchange>>>>>>>>>>>>");
        log.info("kycExchangeRequestDto>>>>>>", kycExchangeDto);
        throw new KycExchangeException("NOT_IMPLEMENTED");
    }

    @Override
    public SendOtpResult sendOtp(String relyingPartyId, String clientId, SendOtpDto sendOtpDto)
            throws SendOtpException {
        log.info("OTP send request initiated for clientId: {}", clientId);
        log.info("OTP send request initiated for relyingPartyId: {}", relyingPartyId);
        log.info("OTP send request initiated for sendOtpDto: {}", sendOtpDto);
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
            log.info("Started sending OTP for transactionId : {}", sendOtpDto.getTransactionId());
            OtpRequestDto otpRequestDto = new OtpRequestDto(sendOtpDto.getIndividualId(), channelToSend);
            log.info(">>>>>>>>>>>>>>getIndividualId : {}", sendOtpDto.getIndividualId());
            log.info(">>>>>>>>>>>>> channelToSend : {}",channelToSend );

            String requestBody = objectMapper.writeValueAsString(otpRequestDto);
            log.info(">>>>>>>>>>>>> requestBody : {}",requestBody );
            log.info("Sending OTP request to URL: {}", otpSendUrl);
            log.info("Authorization header: Bearer {}...",
                    credIssuerBearerToken != null && credIssuerBearerToken.length() > 10
                            ? credIssuerBearerToken.substring(0, 10) + "..."
                            : "N/A");
            String individualId = sendOtpDto.getIndividualId();
            log.info(">>>>>>>>>>>>> individualId : {}",individualId );

            String finalOtpApiUrl = otpSendUrl + individualId;
            log.info(">>>>>>>>>>>>> finalOtpApiUrl : {}",finalOtpApiUrl );
            log.info("Sending OTP request to dynamic URL: {}", finalOtpApiUrl);
            HttpHeaders headers = new HttpHeaders();
            log.info("Sending OTP request to dynamic header: {}", headers);
            headers.set("Authorization", "Bearer " + credIssuerBearerToken);
            HttpEntity<String> entity = new HttpEntity<>(headers);
//            RequestEntity<String> requestEntity = RequestEntity
//                    .post(UriComponentsBuilder.fromUriString(finalOtpApiUrl).build().toUri())
//                    .header("Authorization", "Bearer " + credIssuerBearerToken)
//                    .contentType(MediaType.APPLICATION_JSON)
//                    .body(requestBody);

            ResponseEntity<Map<String, Object>> responseEntity = restTemplate.exchange(
                    finalOtpApiUrl,
                    HttpMethod.GET,
                    entity,
                    new ParameterizedTypeReference<Map<String, Object>>() {});

            log.info("Received response with status: {}", responseEntity.getStatusCode());
            log.info("Response body: {}", responseEntity.getBody());
            if (responseEntity.getStatusCode().is2xxSuccessful()) {
                log.info("Successfully initiated OTP send request for transactionId: {}", sendOtpDto.getTransactionId());
                SendOtpResult result = new SendOtpResult();
                log.debug("Response body: {}",result);

                result.setTransactionId(sendOtpDto.getTransactionId());
                return result;


            } else {
                log.error("Failed to send OTP. Service returned status: {}", responseEntity.getStatusCode());
                throw new SendOtpException(io.mosip.esignet.api.util.ErrorConstants.SEND_OTP_FAILED);
            }
        } catch (Exception e) {
            log.error("Exception while sending OTP for transactionId : {}", sendOtpDto.getTransactionId(), e);
            throw new SendOtpException(io.mosip.esignet.api.util.ErrorConstants.SEND_OTP_FAILED);
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

    private KycAuthResult validateOtpAuth(KycAuthDto kycAuthDto, AuthChallenge authChallenge) throws KycAuthException {
        String credential_id = kycAuthDto.getIndividualId();
        String transactionId = kycAuthDto.getTransactionId();
        String otp = authChallenge.getChallenge();

        log.info("Attempting to validate OTP for kycAuthDto: {}", kycAuthDto);
        log.info("Attempting to validate OTP for authChallenge: {}", authChallenge);
        try {
            log.info("Preparing OTP verification request for transactionId: {} and credential_id: {}",
                    transactionId, credential_id);
            HttpHeaders headers = new HttpHeaders();
            OtpVerifyRequestDto verifyRequestDto = new OtpVerifyRequestDto(credential_id, otp);
            log.info("Attempting to validate OTP for verifyRequestDto: {}", verifyRequestDto);
            String requestBody = objectMapper.writeValueAsString(verifyRequestDto);
            log.info("Attempting to validate OTP for requestBody: {}", requestBody);
            RestTemplate restTemplate = new RestTemplate();
            log.info("Serialized OTP request body: {}", requestBody);
            log.info("Serialized OTP otpVerifyUrl: {}", otpVerifyUrl);
            log.info("Serialized OTP credIssuerBearerToken: {}", credIssuerBearerToken);
            RequestEntity<String> requestEntity = RequestEntity
                    .post(UriComponentsBuilder.fromUriString(otpVerifyUrl).build().toUri())
                    .header("Authorization", "Bearer " + credIssuerBearerToken)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(requestBody);

            ResponseEntity<Map<String, Object>> responseEntity = restTemplate.exchange(requestEntity,
                    new ParameterizedTypeReference<Map<String, Object>>() {});

            if (responseEntity.getStatusCode().is2xxSuccessful() && responseEntity.getBody() != null) {
                log.info("OTP validation successful for transactionId: {}", transactionId);
                KycAuthResult kycAuthResult = new KycAuthResult();
                log.info("OTP validation successful for kycAuthResult: {}", kycAuthResult);

                // Use the credential_id directly since the registry lookup is removed.
                kycAuthResult.setKycToken(credential_id);
                kycAuthResult.setPartnerSpecificUserToken(credential_id);
                log.info("OTP validation successful for kycAuthResult: {}", kycAuthResult);
                return kycAuthResult;
            } else {
                log.error("OTP validation failed for transactionId: {}. Status: {}",
                        transactionId, responseEntity.getStatusCode());
                throw new KycAuthException("AUTH_FAILED");
            }
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.UNAUTHORIZED || e.getStatusCode() == HttpStatus.FORBIDDEN) {
                log.warn("OTP validation failed for transaction: {} with status {}", transactionId, e.getStatusCode());
            } else {
                log.error("HTTP client error during OTP validation for transaction: {}", transactionId, e);
            }
            throw new KycAuthException("AUTH_FAILED");
        } catch (Exception e) {
            log.error("Exception during OTP validation for transaction: {}", transactionId, e);
            throw new KycAuthException("AUTH_FAILED");
        }
    }

    // --- DTO Inner classes for OTP ---
    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    private static class OtpRequestDto {
        private String individualId;
        private String channel; // e.g., "EMAIL", "SMS"
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    private static class OtpVerifyRequestDto {
        private String credential_id;
        private String otp;
    }
}

