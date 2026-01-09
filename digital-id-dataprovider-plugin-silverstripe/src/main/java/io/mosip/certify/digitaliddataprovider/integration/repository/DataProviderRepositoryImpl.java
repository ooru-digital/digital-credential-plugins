package io.mosip.certify.digitaliddataprovider.integration.repository;

import jakarta.persistence.*;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


@Repository(value = "dataProviderRepository")
public class DataProviderRepositoryImpl implements DataProviderRepository {
    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public Map<String, Object> fetchQueryResult(String id, String queryString) {
        Query query = entityManager.createNativeQuery(queryString, Tuple.class);
        query.setParameter("id", id);
        List<Tuple> list = query.getResultList();
        List<Map<String, Object>> result = convertTuplesToMap(list);
        return result.getFirst();
    }

    public static List<Map<String, Object>> convertTuplesToMap(List<Tuple> tuples) {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Tuple single : tuples) {
            Map<String, Object> tempMap = new HashMap<>();
            for (TupleElement<?> key : single.getElements()) {
                tempMap.put(key.getAlias(), single.get(key));
            }
            result.add(tempMap);
        }
        return result;
    }
}