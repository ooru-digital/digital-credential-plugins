package io.mosip.certify.digitaliddataprovider.integration.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.mosip.certify.api.exception.DataProviderExchangeException;
import io.mosip.certify.digitaliddataprovider.integration.repository.DataProviderRepository;
import lombok.extern.slf4j.Slf4j;

import io.mosip.certify.digitaliddataprovider.integration.config.CredentialIssuerConfigProperties;
import io.mosip.certify.digitaliddataprovider.integration.config.CredentialIssuerConfig;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.env.Environment;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import org.springframework.http.HttpHeaders;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONArray;

@ConditionalOnProperty(value = "mosip.certify.integration.data-provider-plugin", havingValue = "DigitalIdProviderPlugin")
@Component
@Slf4j
public class DigitalIdDataProviderPlugin implements ExtendedDataProviderPlugin {

    @Autowired
    private DataProviderRepository dataProviderRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @Value("${mosip.data-provider.url}")
    private String dataProviderUrl;

    @Autowired
    private RestTemplate restTemplate;

    @Value("${mosip.data-provider.token}")
    private String HARDCODED_BEARER_TOKEN;

    @Value("${credissuer.publish.url}")
    private String publishUrl;


    @Autowired
    private CredentialIssuerConfigProperties configProperties;

    @Override
    public JSONObject fetchData(Map<String, Object> identityDetails) throws DataProviderExchangeException {
        try {
            String credentialType = (String) identityDetails.get("credential_type");
            CredentialIssuerConfig config = configProperties.getConfigs().get(credentialType);

            if (config == null) {
                throw new RuntimeException("No issuer configuration found for credential type: " + credentialType);
            }

            String templateId = config.getTemplateId();
            String dataUniqueId = (String) identityDetails.get("https://za.dpi-poc.com/email");

            if (dataUniqueId == null) {
                throw new DataProviderExchangeException("Missing data_unique_id in identityDetails");
            }

            Map<String, Object> requestPayload = new HashMap<>();
            requestPayload.put("template_entity_id", templateId);
            requestPayload.put("data_unique_id", dataUniqueId);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(HARDCODED_BEARER_TOKEN);

            HttpEntity<Map<String, Object>> requestEntity = new HttpEntity<>(requestPayload, headers);
            ResponseEntity<Map> responseEntity = restTemplate.exchange(
                    dataProviderUrl,
                    HttpMethod.GET, 
                    requestEntity,
                    Map.class
            );

            if (responseEntity.getStatusCode().is2xxSuccessful() && responseEntity.getBody() != null) {
                Map<String, Object> responseMap = responseEntity.getBody();
                Object data = responseMap.get("raw_data");

                if (data == null) {
                    log.warn("Data field is null in the response from data provider");
                    throw new DataProviderExchangeException("No Data Found");
                }

                if (data instanceof Map) {
                    log.info("Fetched JSON data from data provider plugin successfully");
                    return new JSONObject((Map<?, ?>) data);
                } else if (data instanceof String) {
                    log.info("Fetched string data from data provider plugin successfully");
                    return new JSONObject((String) data);
                }

                log.error("Unexpected data type in 'raw_data' field: {}", data.getClass().getName());
                throw new DataProviderExchangeException("Invalid data format received from data provider");
            }

            log.warn("Non-2xx response or null body from data provider: status={}, body={}",
                    responseEntity.getStatusCode(), responseEntity.getBody());
            throw new DataProviderExchangeException("No Data Found");

        } catch (Exception e) {
            log.error("Failed to fetch JSON data from data provider plugin", e);
            throw new DataProviderExchangeException("ERROR_FETCHING_IDENTITY_DATA");
        }
    }


    @Override
    public void pushCredential(JSONObject signedCredentialJson) {
        try {
            String credentialType = null;
            if (signedCredentialJson.has("type")) {
                JSONArray typesArray = signedCredentialJson.getJSONArray("type");
                if (typesArray.length() > 1) {
                    credentialType = typesArray.getString(1);
                }
            }
            log.info("Credential Type extracted: {}", credentialType);

            CredentialIssuerConfig config = configProperties.getConfigs().get(credentialType);

            String orgCode = config.getOrgCode();
            String email = config.getEmail();
            String templateId = config.getTemplateId();

            ObjectMapper mapper = new ObjectMapper();
            ObjectNode signedJsonNode = (ObjectNode) mapper.readTree(signedCredentialJson.toString());
            JsonNode credentialSubject = signedJsonNode.path("credentialSubject");

            if (credentialSubject.isMissingNode() || credentialSubject.isNull()) {
                log.error("credentialSubject not found in signed VC!");
                return;
            }

            ArrayNode credentialDataArray = mapper.createArrayNode();
            ObjectNode credData = mapper.createObjectNode();
            credentialSubject.fields().forEachRemaining(entry -> {
                String key = entry.getKey();
                if (!"id".equals(key) && !"type".equals(key)) {
                    credData.set(key, entry.getValue());
                }
            });
            credentialDataArray.add(credData);

            ObjectNode issuerInfo = mapper.createObjectNode();
            issuerInfo.put("org_code", orgCode);
            issuerInfo.put("email", email);

            ObjectNode finalPayload = mapper.createObjectNode();
            finalPayload.set("credential_data", credentialDataArray);
            finalPayload.set("issuer_info", issuerInfo);
            finalPayload.put("issuer_credential_template_id", templateId);
            finalPayload.set("signed_json", mapper.createObjectNode().set("credential", signedJsonNode));

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(HARDCODED_BEARER_TOKEN);
            System.out.println("finalPayload   " +finalPayload.toString());

            HttpEntity<String> request = new HttpEntity<>(finalPayload.toString(), headers);
            ResponseEntity<String> response = restTemplate.exchange(
                    publishUrl,
                    HttpMethod.POST,
                    request,
                    String.class
            );

            log.info("Credential pushed to CredIssuer successfully: status={}, body={}",
                    response.getStatusCode(), response.getBody());
        } catch (Exception e) {
            log.error("Failed to push credential to CredIssuer", e);
            throw new RuntimeException("Failed to push credential due to exception: " + e.getMessage(), e);
        }
    }
}
