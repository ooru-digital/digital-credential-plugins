package io.mosip.certify.postgresdataprovider.integration;

import io.mosip.certify.api.exception.DataProviderExchangeException;
import io.mosip.certify.digitaliddataprovider.integration.repository.DataProviderRepository;
import io.mosip.certify.digitaliddataprovider.integration.service.PostgresDataProviderPlugin;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.LinkedHashMap;
import java.util.Map;

@RunWith(MockitoJUnitRunner.class)
public class PostgresDataProviderPluginTest {
    @Mock
    DataProviderRepository dataProviderRepository;

    @InjectMocks
    PostgresDataProviderPlugin postgresDataProviderPlugin = new PostgresDataProviderPlugin();

    @Before
    public void setup() {
        LinkedHashMap<String, String> scopeQueryMapping = new LinkedHashMap<>();
        scopeQueryMapping.put("test_vc_ldp", "test_query");
        ReflectionTestUtils.setField(postgresDataProviderPlugin, "scopeQueryMapping", scopeQueryMapping);
        Map<String, Object> queryResult = Map.of("id","1234567", "name", "John Doe", "dateOfBirth", "01/01/1980", "phoneNumber", "012345", "email", "john@test.com", "landArea", 100.24);
        Mockito.when(dataProviderRepository.fetchQueryResult("1234567", "test_query")).thenReturn(queryResult);
    }

    @Test
    public void fetchJsonDataWithValidIndividualId_thenPass() throws DataProviderExchangeException, JSONException {
        JSONObject jsonObject = postgresDataProviderPlugin.fetchData(Map.of("sub", "1234567", "client_id", "CLIENT_ID", "scope", "test_vc_ldp"));
        Assert.assertNotNull(jsonObject);
        Assert.assertNotNull(jsonObject.get("name"));
        Assert.assertNotNull(jsonObject.get("dateOfBirth"));
        Assert.assertNotNull(jsonObject.get("phoneNumber"));
        Assert.assertNotNull(jsonObject.get("email"));
        Assert.assertNotNull(jsonObject.get("landArea"));
        Assert.assertEquals("John Doe", jsonObject.get("name"));
        Assert.assertEquals("01/01/1980", jsonObject.get("dateOfBirth"));
        Assert.assertEquals("012345", jsonObject.get("phoneNumber"));
        Assert.assertEquals("john@test.com", jsonObject.get("email"));
        Assert.assertEquals(100.24, jsonObject.get("landArea"));
    }

    @Test
    public void fetchJsonDataWithInValidIndividualId_thenFail() throws DataProviderExchangeException, JSONException {
        try {
            postgresDataProviderPlugin.fetchData(Map.of("sub", "12345678", "client_id", "CLIENT_ID", "scope", "test_vc_ldp"));
        } catch (DataProviderExchangeException e) {
            Assert.assertEquals("ERROR_FETCHING_DATA_RECORD_FROM_TABLE", e.getMessage());
        }
    }

    @Test
    public void fetchJsonDataWithInValidScope_thenFail() throws DataProviderExchangeException, JSONException {
        try {
            postgresDataProviderPlugin.fetchData(Map.of("sub", "1234567", "client_id", "CLIENT_ID", "scope", "sample_vc_ldp"));
        } catch (DataProviderExchangeException e) {
            Assert.assertEquals("ERROR_FETCHING_DATA_RECORD_FROM_TABLE", e.getMessage());
        }
    }
}