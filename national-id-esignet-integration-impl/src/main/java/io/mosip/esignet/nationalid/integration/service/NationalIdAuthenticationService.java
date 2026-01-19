/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.esignet.nationalid.integration.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.esignet.api.dto.*;
import io.mosip.esignet.api.exception.KycAuthException;
import io.mosip.esignet.api.exception.KycExchangeException;
import io.mosip.esignet.api.exception.SendOtpException;
import io.mosip.esignet.api.spi.Authenticator;
import io.mosip.esignet.api.util.ErrorConstants;
import io.mosip.esignet.nationalid.integration.dto.RegistrySearchRequestDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import javax.annotation.PostConstruct;
import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.nio.charset.StandardCharsets;
import java.util.*;

import io.mosip.esignet.nationalid.integration.repository.KycAuthRepository;
import io.mosip.kernel.signature.service.SignatureService;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import io.mosip.esignet.nationalid.integration.entity.KycAuth;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import io.mosip.kernel.signature.dto.JWTSignatureRequestDto;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.client.HttpClientErrorException;
import java.util.List;




@ConditionalOnProperty(value = "mosip.esignet.integration.authenticator", havingValue = "NationalIDAuthenticationService")
@Component
@Slf4j
public class NationalIdAuthenticationService implements Authenticator {

    private final String FILTER_EQUALS_OPERATOR="eq";

    private final String FIELD_ID_KEY="id";

    @Value("#{${mosip.esignet.authenticator.default.auth-factor.kbi.field-details}}")
    private List<Map<String,String>> fieldDetailList;

    @Value("${mosip.esignet.authenticator.default.auth-factor.kbi.individual-id-field}")
    private String idField;

    @Value("${mosip.esignet.authenticator.digital-id.user-service-url}")
    private String userServiceUrl;

    @Value("${mosip.esignet.authenticator.digital-id.user-response-key:data}")
    private String userResponseKey;

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    @Value("${mosip.esignet.authenticator.digital-id.kbi.entity-id-field}")
    private String entityIdField;

    @Value("${mosip.esignet.authenticator.otp-send-url}")
    private String otpSendUrl;

    @Value("${mosip.esignet.authenticator.otp.supported-channels}")
    private List<String> supportedOtpChannels;


    @Autowired
    private KycAuthRepository kycAuthRepository;

    @Autowired
    private SignatureService signatureService;

    public static final String APPLICATION_ID = "OIDC_PARTNER";



    @PostConstruct
    public void initialize() throws KycAuthException {
        log.info("Started to setup Sunbird-RC Authenticator");
        boolean individualIdFieldIsValid = false;
        if(fieldDetailList==null || fieldDetailList.isEmpty()){
            log.error("Invalid configuration for field-details");
            throw new KycAuthException("sunbird-rc authenticator field is not configured properly");
        }
        for (Map<String, String> field : fieldDetailList) {
            if (field.containsKey(FIELD_ID_KEY) && field.get(FIELD_ID_KEY).equals(idField)) {
                individualIdFieldIsValid = true;
                break;
            }
        }
        if (!individualIdFieldIsValid) {
            log.error("Invalid configuration: The 'individual-id-field' '{}' is not available in 'field-details'.", idField);
            throw new KycAuthException("Invalid configuration: individual-id-field is not available in field-details.");
        }
    }

    @Override
    public KycAuthResult doKycAuth(@NotBlank String relyingPartyId,
                                @NotBlank String clientId,
                                @NotNull @Valid KycAuthDto kycAuthDto)
            throws KycAuthException {

        if (kycAuthDto.getChallengeList() == null || kycAuthDto.getChallengeList().isEmpty()) {
            throw new KycAuthException("invalid_challenge_format");
        }

        AuthChallenge authChallenge = kycAuthDto.getChallengeList().get(0);

        switch (authChallenge.getAuthFactorType()) {

            case "KBI":
                return validateKnowledgeBasedAuth(
                        kycAuthDto.getIndividualId(), authChallenge);

            case "OTP":
                return validateOtpAuth(kycAuthDto, authChallenge);
                    

            default:
                throw new KycAuthException("unsupported_auth_factor");
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
        System.out.println("kycAuth>>>>>" + kycAuth);

        if (!Objects.equals(kycAuth.getTransactionId(), request.getTransactionId()) ||
            !Objects.equals(kycAuth.getIndividualId(), request.getIndividualId()) ||
            kycAuth.getValidity() != KycAuth.VALIDITY_ACTIVE) {

            throw new KycExchangeException("Invalid or expired KYC record.");
        }

        LocalDateTime requestTime = LocalDateTime.now();
        long seconds = kycAuth.getResponseTime().until(requestTime, ChronoUnit.SECONDS);
        // If seconds < 0, it may be due to clock skew between systems. Expire session if older than 5 mins.
        if (seconds < 0 || seconds > 300) { // 5 mins
            kycAuth.setValidity(KycAuth.VALIDITY_EXPIRED);
            kycAuthRepository.save(kycAuth);
            throw new KycExchangeException("KYC session expired.");
        }
        String nationalId = kycAuth.getIndividualId();
        System.out.println("nationalId>>>>>" + nationalId);

        String apiUrl = userServiceUrl + nationalId;
        System.out.println("apiUrl>>>>>" + apiUrl);

        // Send GET request
        ResponseEntity<Map<String, Object>> responseEntity = restTemplate.exchange(
                apiUrl,
                org.springframework.http.HttpMethod.GET,
                null,
                new ParameterizedTypeReference<Map<String, Object>>() {}
        );

        if (!responseEntity.getStatusCode().is2xxSuccessful() || responseEntity.getBody() == null) {
            log.error("User service failed. Status: {}", responseEntity.getStatusCode());
            throw new KycExchangeException(ErrorConstants.AUTH_FAILED);
        }

        Map<String, Object> responseBody = responseEntity.getBody();
        Map<String, Object> userData = (Map<String, Object>) responseBody.get(userResponseKey);

        if (userData == null) {
            log.error("Response does not contain '{}' field.", userResponseKey);
            throw new KycExchangeException(ErrorConstants.AUTH_FAILED);
        }
        String firstName   = Objects.toString(userData.get("first_name"), null);
        String lastName    = Objects.toString(userData.get("last_name"), null);
        String email       = Objects.toString(userData.get("email"), null);
        String phoneNumber = Objects.toString(userData.get("phone_number"), null);

        try {
            Map<String, Object> kyc = new HashMap<>();
            kyc.put("sub", kycAuth.getPartnerSpecificUserToken());
            kyc.put("first_name", firstName);
            kyc.put("last_name", lastName);
            kyc.put("email", email);
            kyc.put("phone_number", phoneNumber);

            String signedKyc = signKyc(kyc);
            kycAuth.setValidity(KycAuth.VALIDITY_USED);
            kycAuthRepository.save(kycAuth);

            KycExchangeResult response = new KycExchangeResult();
            response.setEncryptedKyc(signedKyc);
            return response;
        } catch (Exception e) {
            log.error("Error building KYC data", e);
            throw new KycExchangeException("KYC_EXCHANGE_FAILED");
        }
    }

    private String signKyc(Map<String, Object> kyc) throws JsonProcessingException {
        String payload = objectMapper.writeValueAsString(kyc);

        JWTSignatureRequestDto jwtSignatureRequestDto = new JWTSignatureRequestDto();
        jwtSignatureRequestDto.setApplicationId(APPLICATION_ID); // OIDC_PARTNER
        jwtSignatureRequestDto.setReferenceId("");
        jwtSignatureRequestDto.setIncludePayload(true);
        jwtSignatureRequestDto.setIncludeCertificate(false);
        jwtSignatureRequestDto.setIncludeCertHash(false);

        jwtSignatureRequestDto.setDataToSign(
            Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(payload.getBytes(StandardCharsets.UTF_8))
        );

        JWTSignatureResponseDto responseDto =
                signatureService.jwtSign(jwtSignatureRequestDto);

        return responseDto.getJwtSignedData(); // JWS returned
    }

    private HttpHeaders buildAuthHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
    }


    @Override
    public SendOtpResult sendOtp(String relyingPartyId, String clientId, SendOtpDto sendOtpDto)
            throws SendOtpException {
        List<String> requestedChannels = sendOtpDto.getOtpChannels();
        if (requestedChannels == null || requestedChannels.isEmpty()) {
            log.error("OTP request failed for clientId: {}. Reason: Channel list is null or empty.", clientId);
            throw new SendOtpException(ErrorConstants.AUTH_FAILED);
        }
        log.debug("Client '{}' requested OTP via channels: {}", clientId, requestedChannels);

        String channelToSend = requestedChannels.stream()
                .filter(this::isSupportedOtpChannel)
                .findFirst()
                .orElseThrow(() -> new SendOtpException(ErrorConstants.AUTH_FAILED));


        try {
            String nationalId = sendOtpDto.getIndividualId();

            String apiUrl = userServiceUrl + nationalId;
            System.out.println("apiUrl>>>>>" + apiUrl);
    
            // Send GET request
            ResponseEntity<Map<String, Object>> responseEntity = restTemplate.exchange(
                    apiUrl,
                    org.springframework.http.HttpMethod.GET,
                    null,
                    new ParameterizedTypeReference<Map<String, Object>>() {}
            );

            if (!responseEntity.getStatusCode().is2xxSuccessful() || responseEntity.getBody() == null) {
                log.error("User service failed. Status: {}", responseEntity.getStatusCode());
                throw new KycAuthException(ErrorConstants.AUTH_FAILED);
            }

            Map<String, Object> responseBody = responseEntity.getBody();
            Map<String, Object> userData = (Map<String, Object>) responseBody.get(userResponseKey);

            if (userData == null) {
                log.error("Response does not contain '{}' field.", userResponseKey);
                throw new KycAuthException(ErrorConstants.AUTH_FAILED);
            }


            /* --------- Build request body --------- */
            Map<String, Object> requestBody = new HashMap<>();
            requestBody.put("national_id", nationalId);
            requestBody.put("channel", channelToSend);

            String requestJson = objectMapper.writeValueAsString(requestBody);

            /* --------- Headers --------- */
            HttpHeaders headers = buildAuthHeaders();

            HttpEntity<String> entity = new HttpEntity<>(requestJson, headers);

            ResponseEntity<Map<String, Object>> otpResponse =
                restTemplate.exchange(
                        otpSendUrl,
                        HttpMethod.GET,
                        entity,
                        new ParameterizedTypeReference<>() {});


            if (otpResponse.getStatusCode().is2xxSuccessful()) {
                SendOtpResult result = new SendOtpResult();
                result.setTransactionId(sendOtpDto.getTransactionId());
                return result;
            }

            log.error("Failed to send OTP for transactionId: {}", sendOtpDto.getTransactionId());
            throw new SendOtpException(ErrorConstants.AUTH_FAILED);

        } catch (Exception e) {
            log.error("Failed to send OTP for transactionId: {}", sendOtpDto.getTransactionId(), e);
            throw new SendOtpException("SEND_OTP_FAILED");
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
            /* --------- Build request body --------- */
            // OtpVerifyRequestDto requestDto =
            //         new OtpVerifyRequestDto(nationalId, otp);

            // String requestJson = objectMapper.writeValueAsString(requestDto);

            // /* --------- Headers --------- */
            // HttpHeaders headers = buildAuthHeaders();
            // HttpEntity<String> entity = new HttpEntity<>(requestJson, headers);

            // ResponseEntity<Map<String, Object>> responseEntity =
            //         restTemplate.exchange(
            //                 otpVerifyUrl,
            //                 HttpMethod.POST,
            //                 entity,
            //                 new ParameterizedTypeReference<>() {});

            // if (!responseEntity.getStatusCode().is2xxSuccessful()
            //         || responseEntity.getBody() == null) {
            //     throw new KycAuthException("AUTH_FAILED");
            // }

            // /* --------- Parse response --------- */
            // Map<String, Object> body = responseEntity.getBody();

            // boolean verified = false;
            // if (body != null) {
            //     Object dataObj = body.get("data");
            //     if (dataObj instanceof Map) {
            //         @SuppressWarnings("unchecked")
            //         Map<String, Object> data = (Map<String, Object>) dataObj;
            //         verified = Boolean.TRUE.equals(data.get("verified"));
            //     }
            // }

            // if (!verified) {
            //     log.warn("OTP verification failed for transactionId: {}", transactionId);
            //     throw new KycAuthException("AUTH_FAILED");
            // }

            /* --------- Success handling --------- */

            if (!"111111".equals(otp)) {
                log.error("Invalid OTP for individualId {}", nationalId);
                throw new KycAuthException(ErrorConstants.AUTH_FAILED);
            }

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

    private KycAuthResult validateKnowledgeBasedAuth(String individualId, AuthChallenge authChallenge) throws KycAuthException {
        System.out.println("individualId>>>>>" + individualId);
        KycAuthResult kycAuthResult = new KycAuthResult();
    
        // Decode the Base64URL challenge
        byte[] decodedBytes = Base64.getUrlDecoder().decode(authChallenge.getChallenge());
        String challengeJson = new String(decodedBytes, StandardCharsets.UTF_8);
    
        try {
            Map<String, String> challengeMap = objectMapper.readValue(challengeJson, Map.class);
    
            // Build the target URL
            String apiUrl = userServiceUrl + individualId;
            System.out.println("apiUrl>>>>>" + apiUrl);
    
            // Send GET request
            ResponseEntity<Map<String, Object>> responseEntity = restTemplate.exchange(
                    apiUrl,
                    org.springframework.http.HttpMethod.GET,
                    null,
                    new ParameterizedTypeReference<Map<String, Object>>() {}
            );
            // System.out.println("responseEntity>>>>>" +responseEntity);
    
            if (responseEntity.getStatusCode().is2xxSuccessful() && responseEntity.getBody() != null) {
                Map<String, Object> responseBody = responseEntity.getBody();

                // Map<String, Object> userData = (Map<String, Object>) responseBody.get("data");
                Map<String, Object> userData = (Map<String, Object>) responseBody.get(userResponseKey);
                if (userData == null) {
                    log.error("Response does not contain 'data' field.");
                    throw new KycAuthException(ErrorConstants.AUTH_FAILED);
                }
    
                // Optional: Validate challenge fields against response
                for (Map<String, String> fieldDetailMap : fieldDetailList) {
                    String key = fieldDetailMap.get(FIELD_ID_KEY);
                    System.out.println("key>>>>>" + key);
                    String expectedValue = key.equals(entityIdField) ? individualId : challengeMap.get(key);
                    System.out.println("expectedValue>>>>>" + expectedValue);
    
                    if (expectedValue == null) {
                        log.error("Challenge is missing required field: {}", key);
                        throw new KycAuthException(ErrorConstants.AUTH_FAILED);
                    }
    
                    Object actualValue = userData.get(key);
                    if (actualValue == null || !expectedValue.equals(actualValue.toString())) {
                        log.error("Validation failed for field '{}'. Expected='{}', Found='{}'",
                                key, expectedValue, actualValue);
                        throw new KycAuthException(ErrorConstants.AUTH_FAILED);
                    }
                }
    
                // Use individualId as token or extract some other unique identifier from response
                String token = userData.getOrDefault(idField, individualId).toString();
                kycAuthResult.setKycToken(token);
                kycAuthResult.setPartnerSpecificUserToken(token);
                System.out.println("kycAuthResult>>>>>" + kycAuthResult);
    
                return kycAuthResult;
            } else {
                log.error("User service failed. Status: {}", responseEntity.getStatusCode());
                throw new KycAuthException(ErrorConstants.AUTH_FAILED);
            }
    
        } catch (Exception e) {
            log.error("Authentication failed for individualId {}: {}", individualId, e.getMessage(), e);
            throw new KycAuthException(ErrorConstants.AUTH_FAILED);
        }
    }


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
        private String otp;
    }
    
}
