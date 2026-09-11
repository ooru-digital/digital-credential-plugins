package io.mosip.certify.digitaliddataprovider.integration.service;


import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.api.exception.DataProviderExchangeException;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.digitaliddataprovider.integration.repository.DataProviderRepository;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.*;

@ConditionalOnProperty(value = "mosip.certify.integration.data-provider-plugin", havingValue = "DigitalIdProviderPlugin")
@Component
@Slf4j
public class DigitalIdDataProviderPlugin implements DataProviderPlugin {

    @Autowired
    private DataProviderRepository dataProviderRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @Value("${mosip.data-provider.url}")
    private String dataProviderUrl;

    @Autowired
    private RestTemplate restTemplate;

    @Override
    public JSONObject fetchData(Map<String, Object> identityDetails) throws DataProviderExchangeException {
        try {
            String individualId = (String) identityDetails.get("sub");
            ResponseEntity<Map<String, Object>> responseEntity = restTemplate.exchange(
                dataProviderUrl + individualId,
                    org.springframework.http.HttpMethod.GET,
                    null,
                    new ParameterizedTypeReference<Map<String, Object>>() {}
            );

            if (responseEntity.getStatusCode().is2xxSuccessful() && responseEntity.getBody() != null) {
                Map<String, Object> responseMap = responseEntity.getBody();
                Object data = responseMap.get("data");
                if (data == null) {
                    log.warn("Data field is null in the response from Welerantt data provider");
                    throw new DataProviderExchangeException("No Data Found");
                }

                if (data instanceof Map) {
                    return new JSONObject((Map<?, ?>) data);
                } else {
                    log.error("Unexpected data type in 'Data' field: {}", data.getClass().getName());
                    throw new DataProviderExchangeException("Invalid data format received from data provider");
                }
            } else {
                log.warn("Non-2xx response or null body from data provider: status={}, body={}",
                            responseEntity.getStatusCode(), responseEntity.getBody());
            }
        } catch (Exception e) {
            log.error("Failed to fetch json data from Welerantt data provider plugin", e);
            throw new DataProviderExchangeException("ERROR_FETCHING_IDENTITY_DATA");
        }

        throw new DataProviderExchangeException("No Data Found");
    }
}