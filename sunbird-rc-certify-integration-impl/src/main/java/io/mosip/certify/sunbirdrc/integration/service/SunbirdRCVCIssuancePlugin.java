/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.sunbirdrc.integration.service;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.exception.VCIExchangeException;
import io.mosip.certify.api.spi.VCIssuancePlugin;
import io.mosip.certify.api.util.ErrorConstants;
import io.mosip.certify.sunbirdrc.integration.dto.RegistrySearchRequestDto;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.exception.ResourceNotFoundException;
import org.apache.velocity.runtime.RuntimeConstants;
import org.apache.velocity.runtime.resource.loader.URLResourceLoader;
import org.apache.velocity.tools.generic.DateTool;
import org.json.JSONArray;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import org.springframework.cache.CacheManager;
import org.springframework.http.HttpHeaders;

import io.mosip.esignet.core.dto.OIDCTransaction;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.PrintWriter;
import java.util.Base64;
import java.util.Objects;

import java.time.ZoneOffset;
import java.time.LocalDateTime;

import javax.crypto.Cipher;
import java.security.Key;
import io.mosip.kernel.core.keymanager.spi.KeyStore;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerConstant;
import io.mosip.kernel.keymanagerservice.entity.KeyAlias;
import io.mosip.kernel.keymanagerservice.helper.KeymanagerDBHelper;

@ConditionalOnProperty(value = "mosip.certify.integration.vci-plugin", havingValue = "SunbirdRCVCIssuancePlugin")
@Component
@Slf4j
public class SunbirdRCVCIssuancePlugin implements VCIssuancePlugin {

    private static final String CREDENTIAL_TYPE_PROPERTY_PREFIX ="mosip.certify.vciplugin.sunbird-rc.credential-type";

    private static final String LINKED_DATA_PROOF_VC_FORMAT ="ldp_vc";

    private static final String TEMPLATE_URL = "template-url";

    private static final String REGISTRY_GET_URL = "registry-get-url";

    private static final String REGISTRY_SEARCH_URL= "registry-search-url";

    private static final String CRED_SCHEMA_ID = "cred-schema-id";

    private static final String CRED_SCHEMA_VESRION = "cred-schema-version";

    private static final String STATIC_VALUE_MAP_ISSUER_ID = "static-value-map.issuerId";

    private static final String CREDENTIAL_OBJECT_KEY = "credential";

    private final String FILTER_EQUALS_OPERATOR = "eq";

    public static final String AES_CIPHER_FAILED = "aes_cipher_failed";

    public static final String OIDC_SERVICE_APP_ID = "CERTIFY_SERVICE";

    private final String PSUT_TOKEN="psut";

    public static final String NO_UNIQUE_ALIAS = "no_unique_alias";

    private Base64.Decoder urlSafeDecoder = Base64.getUrlDecoder();

    @Autowired
    Environment env;

    @Autowired
    ObjectMapper mapper;

    @Autowired
    private KeyStore keyStore;

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private KeymanagerDBHelper dbHelper;

    @Value("${mosip.certify.vciplugin.sunbird-rc.issue-credential-url}")
    String issueCredentialUrl;

    @Value("${io.credissuer.com.get-credential-url}")
    String getCredentialUrl;

    @Value("${mosip.certify.cache.secure.individual-id}")
    private boolean secureIndividualId;

    @Value("${mosip.certify.cache.store.individual-id}")
    private boolean storeIndividualId;

    @Value("${mosip.certify.cache.security.secretkey.reference-id}")
    private String cacheSecretKeyRefId;

    @Value("${mosip.certify.vciplugin.sunbird-rc.enable-psut-based-registry-search:false}")
    private boolean enablePSUTBasedRegistrySearch;

    @Value("${mosip.esignet.authenticator.credissuer.bearer-token}")
    private String credIssuerBeaerToken;

    @Value("${mosip.certify.cache.security.algorithm-name}")
    private String aesECBTransformation;

    @Value("#{'${mosip.certify.vciplugin.sunbird-rc.supported-credential-types}'.split(',')}")
    List<String> supportedCredentialTypes;

    private final Map<String, Template> credentialTypeTemplates = new HashMap<>();

    private final Map<String,Map<String,String>> credentialTypeConfigMap = new HashMap<>();

    private VelocityEngine vEngine;

    @Autowired
    CacheManager cacheManager;
    @Value("${mosip.esignet.ida.vci-user-info-cache}")
    private String userinfoCache;
    private static final String ACCESS_TOKEN_HASH = "accessTokenHash";


    @PostConstruct
    public  void initialize() throws VCIExchangeException {
        vEngine = new VelocityEngine();
        URLResourceLoader urlResourceLoader = new URLResourceLoader() {
            @Override
            public InputStream getResourceStream(String name) throws ResourceNotFoundException {
                try {
                    URL url = new URL(name);
                    URLConnection connection = url.openConnection();
                    return connection.getInputStream();
                } catch (IOException e) {
                    throw new ResourceNotFoundException("Unable to find resource '" + name + "'");
                }
            }
        };
        vEngine.setProperty(RuntimeConstants.RESOURCE_LOADER, "url");
        vEngine.setProperty("url.resource.loader.instance", urlResourceLoader);
        vEngine.init();
        //Validate all the supported VC
        for (String credentialType : supportedCredentialTypes) {
            //validateAndCachePropertiesForCredentialType(credentialType.trim());
        }
    }

    @Override
    public VCResult<JsonLDObject> getVerifiableCredentialWithLinkedDataProof(VCRequestDto vcRequestDto, String holderId,
                                                                             Map<String, Object> identityDetails) throws VCIExchangeException {
        JsonLDObject vcJsonLdObject = null;
        String individualId = null;
        try {
            OIDCTransaction transaction = getOAuthTransaction(identityDetails.get(ACCESS_TOKEN_HASH).toString());
            individualId = getIndividualId(transaction.getIndividualId());
            System.out.println("individualId : "+individualId);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        try {
            VCResult vcResult = new VCResult();
            Map<String,Object> vcResponseMap = fetchCredential(getCredentialUrl + individualId);
            vcJsonLdObject = JsonLDObject.fromJsonObject((Map<String, Object>)vcResponseMap.get(CREDENTIAL_OBJECT_KEY));
            vcResult.setCredential(vcJsonLdObject);
            vcResult.setFormat("ldp_vc");
            return vcResult;
        } catch (Exception e) {
            log.error("Failed to build credissuer response", e);
        }
        throw new VCIExchangeException();
    }

    private Map<String,Object> fetchCredential(String entityUrl) throws VCIExchangeException {
        RequestEntity<Void> requestEntity = RequestEntity
                .get(UriComponentsBuilder.fromUriString(entityUrl).build().toUri())
                .header("Authorization", "Bearer " + credIssuerBeaerToken)  // Set the headers
                .build();
        ResponseEntity<Map<String,Object>> responseEntity = restTemplate.exchange(requestEntity,
                new ParameterizedTypeReference<Map<String,Object>>() {});
        if (responseEntity.getStatusCode().is2xxSuccessful() && responseEntity.getBody() != null) {
            return responseEntity.getBody();
        }else {
            log.error("Credissuer service is not running. Status Code: " , responseEntity.getStatusCode());
            throw new VCIExchangeException(ErrorConstants.VCI_EXCHANGE_FAILED);
        }
    }

    @SuppressWarnings("unchecked")
    public OIDCTransaction getOAuthTransaction(String accessTokenHash) throws Exception {
        if (cacheManager.getCache(userinfoCache) != null) {
            try {
                OIDCTransaction oIDCTransaction = cacheManager.getCache(userinfoCache).get(accessTokenHash, OIDCTransaction.class);	//NOSONAR getCache() will not be returning null here.
                return oIDCTransaction;
            } catch (Exception e) {
                log.error("Exception occured while fetching the cache", e);
                throw new Exception(e);
            }

        }
        throw new Exception("cache_missing>>>>>");
    }

    protected String getIndividualId(String encryptedIndividualId) throws Exception {
        if (!storeIndividualId)
            return null;
        return secureIndividualId ? decryptIndividualId(encryptedIndividualId) : encryptedIndividualId;
    }

    private String decryptIndividualId(String encryptedIndividualId) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance(aesECBTransformation);
            byte[] decodedBytes = b64Decode(encryptedIndividualId);
            cipher.init(Cipher.DECRYPT_MODE, getSecretKeyFromHSM());
            return new String(cipher.doFinal(decodedBytes, 0, decodedBytes.length));
        } catch (Exception e) {
            log.error("Error Cipher Operations of provided secret data.", e);
            throw new Exception(AES_CIPHER_FAILED);
        }
    }

    private Key getSecretKeyFromHSM() throws Exception {
        String keyAlias = getKeyAlias(OIDC_SERVICE_APP_ID, cacheSecretKeyRefId);
        if (Objects.nonNull(keyAlias)) {
            return keyStore.getSymmetricKey(keyAlias);
        }
        throw new Exception(NO_UNIQUE_ALIAS);
    }

    private String getKeyAlias(String keyAppId, String keyRefId) throws Exception {
        Map<String, List<KeyAlias>> keyAliasMap = dbHelper.getKeyAliases(keyAppId, keyRefId,
                LocalDateTime.now(ZoneOffset.UTC));
        List<KeyAlias> currentKeyAliases = keyAliasMap.get(KeymanagerConstant.CURRENTKEYALIAS);
        if (!currentKeyAliases.isEmpty() && currentKeyAliases.size() == 1) {
            return currentKeyAliases.get(0).getAlias();
        }
        log.error("CurrentKeyAlias is not unique. KeyAlias count: {}", currentKeyAliases.size());
        throw new Exception(NO_UNIQUE_ALIAS);
    }



    private byte[] b64Decode(String value) {
        return urlSafeDecoder.decode(value);
    };

    @Override
    public VCResult<String> getVerifiableCredential(VCRequestDto vcRequestDto, String holderId, Map<String, Object> identityDetails) throws VCIExchangeException {
        throw new VCIExchangeException(ErrorConstants.NOT_IMPLEMENTED);
    }

    private Map<String,Object> fetchRegistryObject(String entityUrl) throws VCIExchangeException {
        RequestEntity requestEntity = RequestEntity
                .get(UriComponentsBuilder.fromUriString(entityUrl).build().toUri()).build();
        ResponseEntity<Map<String,Object>> responseEntity = restTemplate.exchange(requestEntity,
                new ParameterizedTypeReference<Map<String,Object>>() {});
        if (responseEntity.getStatusCode().is2xxSuccessful() && responseEntity.getBody() != null) {
            return responseEntity.getBody();
        }else {
            log.error("Sunbird service is not running. Status Code: " ,responseEntity.getStatusCode());
            throw new VCIExchangeException(ErrorConstants.VCI_EXCHANGE_FAILED);
        }
    }


private Map<String, Object> fetchRegistryObjectByPSUT(String registrySearchUrl, String psut) throws VCIExchangeException {

    RegistrySearchRequestDto registrySearchRequestDto=new RegistrySearchRequestDto();
    registrySearchRequestDto.setOffset(0);
    registrySearchRequestDto.setLimit(2);
    Map<String,Map<String,String>> filter=new HashMap<>();
    Map<String,String> psutFilter=new HashMap<>();
    psutFilter.put(FILTER_EQUALS_OPERATOR ,psut);
    filter.put(PSUT_TOKEN ,psutFilter);
    registrySearchRequestDto.setFilters(filter);

    RequestEntity requestEntity =RequestEntity.post(UriComponentsBuilder.fromUriString(registrySearchUrl).build().toUri())
            .contentType(MediaType.APPLICATION_JSON_UTF8)
            .body(registrySearchRequestDto);

    ResponseEntity<List<Map<String,Object>>> responseEntity = restTemplate.exchange(requestEntity,
            new ParameterizedTypeReference<List<Map<String,Object>>>() {});
    if (responseEntity.getStatusCode().is2xxSuccessful() && responseEntity.getBody() != null) {
        List<Map<String,Object>> responseList = responseEntity.getBody();
        if(responseList.size()==1){
            //TODO  This need to be removed since it can contain PII
            log.debug("getting response {}", responseEntity);
        }else{
            log.debug("Registry search returns more than one match,So taking the first. Result size: " + responseList.size());
            log.debug("getting response {}", responseEntity);
            //Todo  we should find a generic way to sort desc based on created date. The idea is we give out the most recent record as VC
        }
        return responseList.get(0);
    }else {
        log.error("Sunbird service is not running. Status Code: " ,responseEntity.getStatusCode());
        throw new VCIExchangeException(ErrorConstants.VCI_EXCHANGE_FAILED);
    }

}

private Map<String,Object> createCredentialIssueRequest(String requestedCredentialType, Map<String,Object> registryObjectMap, VCRequestDto vcRequestDto, String holderId) throws VCIExchangeException {

    Template template=credentialTypeTemplates.get(requestedCredentialType);
    Map<String,String> configMap=credentialTypeConfigMap.get(requestedCredentialType);
    StringWriter writer = new StringWriter();
    VelocityContext context = new VelocityContext();
    Map<String,Object> requestMap=new HashMap<>();
    context.put("date", new DateTool());
    context.put("issuerId", configMap.get(STATIC_VALUE_MAP_ISSUER_ID));
    for (Map.Entry<String, Object> entry : registryObjectMap.entrySet()) {
        String key = entry.getKey();
        Object value = entry.getValue();
        if (value instanceof List) {
            JSONArray jsonArray = new JSONArray((List<String>) value);
            context.put(key, jsonArray);
        } else {
            context.put(key, value);
        }
    }
    template.merge(context, writer);
    try{
        Map<String,Object> credentialObject =mapper.readValue(writer.toString(),Map.class);
        ((Map<String, Object>) credentialObject.get("credentialSubject")).put("id", holderId);
        requestMap.put("credential", credentialObject);
        requestMap.put("credentialSchemaId",configMap.get(CRED_SCHEMA_ID));
        requestMap.put("credentialSchemaVersion",configMap.get(CRED_SCHEMA_VESRION));
        requestMap.put("tags",new ArrayList<>());
    }catch (JsonProcessingException e){
        log.error("Error while parsing the template ",e);
        throw new VCIExchangeException(ErrorConstants.VCI_EXCHANGE_FAILED);
    }
    //TODO  This need to be removed since it can contain PII
    log.info("VC requset is {}",requestMap);
    return requestMap;
}

private Map<String, Object> sendCredentialIssueRequest(Map<String,Object> credentialRequestMap) throws VCIExchangeException {
    try{
        String requestBody=mapper.writeValueAsString(credentialRequestMap);
        RequestEntity requestEntity = RequestEntity
                .post(UriComponentsBuilder.fromUriString(issueCredentialUrl).build().toUri())
                .contentType(MediaType.APPLICATION_JSON_UTF8)
                .body(requestBody);
        ResponseEntity<Map<String,Object>> responseEntity = restTemplate.exchange(requestEntity,
                new ParameterizedTypeReference<Map<String,Object>>(){});
        if (responseEntity.getStatusCode().is2xxSuccessful() && responseEntity.getBody() != null){
            //TODO  This need to be removed since it can contain PII
            log.debug("getting response {}", responseEntity);
            return  responseEntity.getBody();
        }else{
            log.error("Sunbird service is not running. Status Code: " , responseEntity.getStatusCode());
            throw new VCIExchangeException(ErrorConstants.VCI_EXCHANGE_FAILED);
        }
    }catch (Exception e){
        log.error("Unable to parse the Registry Object :{}",credentialRequestMap);
        throw new VCIExchangeException(ErrorConstants.VCI_EXCHANGE_FAILED);
    }
}

private void validateAndCachePropertiesForCredentialType(String credentialType) throws VCIExchangeException {
    Map<String,String> configMap=new HashMap<>();
    validateAndLoadProperty(CREDENTIAL_TYPE_PROPERTY_PREFIX + "." + credentialType + "." + TEMPLATE_URL,TEMPLATE_URL,configMap);
    validateAndLoadProperty(CREDENTIAL_TYPE_PROPERTY_PREFIX + "." + credentialType + "." + REGISTRY_GET_URL,REGISTRY_GET_URL,configMap);
    validateAndLoadProperty(CREDENTIAL_TYPE_PROPERTY_PREFIX + "." + credentialType + "." + CRED_SCHEMA_ID,CRED_SCHEMA_ID,configMap);
    validateAndLoadProperty(CREDENTIAL_TYPE_PROPERTY_PREFIX + "." + credentialType + "." + CRED_SCHEMA_VESRION,CRED_SCHEMA_VESRION,configMap);
    validateAndLoadProperty(CREDENTIAL_TYPE_PROPERTY_PREFIX + "." + credentialType + "." + STATIC_VALUE_MAP_ISSUER_ID,STATIC_VALUE_MAP_ISSUER_ID,configMap);
    validateAndLoadProperty(CREDENTIAL_TYPE_PROPERTY_PREFIX + "." + credentialType + "." + REGISTRY_SEARCH_URL,REGISTRY_SEARCH_URL,configMap);

    String templateUrl = env.getProperty(CREDENTIAL_TYPE_PROPERTY_PREFIX +"." + credentialType + "." + TEMPLATE_URL);
    validateAndCacheTemplate(templateUrl,credentialType);
    // cache configuration with their credential type
    credentialTypeConfigMap.put(credentialType,configMap);
}

private void validateAndLoadProperty(String propertyName, String credentialProp, Map<String,String> configMap) throws VCIExchangeException {
    String propertyValue = env.getProperty(propertyName);
    if (propertyValue == null || propertyValue.isEmpty()) {
        throw new VCIExchangeException("Property " + propertyName + " is not set Properly.");
    }
    configMap.put(credentialProp,propertyValue);
}

private void validateAndCacheTemplate(String templateUrl, String credentialType){
    Template template = vEngine.getTemplate(templateUrl);
    //Todo Validate if all the templates are valid JSON-LD documents
    credentialTypeTemplates.put(credentialType, template);
}

private void validateContextUrl(Template template,List<String> vcRequestContextList) throws VCIExchangeException {
    try{
        StringWriter writer = new StringWriter();
        template.merge(new VelocityContext(),writer);
        Map<String,Object> templateMap = mapper.readValue(writer.toString(),Map.class);
        List<String> contextList=(List<String>) templateMap.get("@context");
        for(String contextUrl:vcRequestContextList){
            if(!contextList.contains(contextUrl)){
                log.error("ContextUrl is not supported");
                throw new VCIExchangeException(ErrorConstants.VCI_EXCHANGE_FAILED);
            }
        }
    }catch ( JsonProcessingException e){
        log.error("Error while parsing the template ",e);
        throw new VCIExchangeException(ErrorConstants.VCI_EXCHANGE_FAILED);
    }
}
}
