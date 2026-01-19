package io.mosip.certify.nationaliddataprovider.integration.repository;


import java.util.Map;

public interface DataProviderRepository {
    Map<String, Object> fetchQueryResult(String id, String queryString);
}