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

    @Validated
    @Override
    public KycAuthResult doKycAuth(@NotBlank String relyingPartyId, @NotBlank String clientId,
                                   @NotNull @Valid KycAuthDto kycAuthDto) throws KycAuthException {

        log.info("Started to build kyc-auth request with transactionId : {} && clientId : {}",
                kycAuthDto.getTransactionId(), clientId);
        try {
            for (AuthChallenge authChallenge : kycAuthDto.getChallengeList()) {
                if(Objects.equals(authChallenge.getAuthFactorType(),"KBI")){
                    return validateKnowledgeBasedAuth(kycAuthDto.getIndividualId(),authChallenge);
                }
                throw new KycAuthException("invalid_challenge_format");
            }
        } catch (KycAuthException e) {
            throw e;
        } catch (Exception e) {
            log.error("KYC-auth failed with transactionId : {} && clientId : {}", kycAuthDto.getTransactionId(),
                    clientId, e);
        }
        throw new KycAuthException(ErrorConstants.AUTH_FAILED);
    }

    @Override
    public KycExchangeResult doKycExchange(String relyingPartyId, String clientId, KycExchangeDto kycExchangeDto)
            throws KycExchangeException {
        throw new KycExchangeException(ErrorConstants.NOT_IMPLEMENTED);
    }

    @Override
    public SendOtpResult sendOtp(String relyingPartyId, String clientId, SendOtpDto sendOtpDto)
            throws SendOtpException {
        throw new SendOtpException(ErrorConstants.NOT_IMPLEMENTED);
        }

    @Override
    public boolean isSupportedOtpChannel(String channel) {
        return false;
    }

    @Override
    public List<KycSigningCertificateData> getAllKycSigningCertificates() {
        return new ArrayList<>();
    }

    private KycAuthResult validateKnowledgeBasedAuth(String individualId, AuthChallenge authChallenge) throws KycAuthException {
        KycAuthResult kycAuthResult = new KycAuthResult();
    
        // Decode the Base64URL challenge
        byte[] decodedBytes = Base64.getUrlDecoder().decode(authChallenge.getChallenge());
        String challengeJson = new String(decodedBytes, StandardCharsets.UTF_8);
    
        try {
            Map<String, String> challengeMap = objectMapper.readValue(challengeJson, Map.class);
            // Build the target URL
            String apiUrl = userServiceUrl + individualId;
            // Send GET request
            ResponseEntity<Map<String, Object>> responseEntity = restTemplate.exchange(
                    apiUrl,
                    org.springframework.http.HttpMethod.GET,
                    null,
                    new ParameterizedTypeReference<Map<String, Object>>() {}
            );
    
            if (responseEntity.getStatusCode().is2xxSuccessful() && responseEntity.getBody() != null) {
                Map<String, Object> responseBody = responseEntity.getBody();
                Map<String, Object> userData = (Map<String, Object>) responseBody.get(userResponseKey);
                if (userData == null) {
                    log.error("Response does not contain 'data' field.");
                    throw new KycAuthException(ErrorConstants.AUTH_FAILED);
                }
    
                // Optional: Validate challenge fields against response
                for (Map<String, String> fieldDetailMap : fieldDetailList) {
                    String key = fieldDetailMap.get(FIELD_ID_KEY);
                    String expectedValue = key.equals(entityIdField) ? individualId : challengeMap.get(key);
    
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
}
