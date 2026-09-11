/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.credissuer.integration.service;


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


@ConditionalOnProperty(value = "mosip.certify.integration.vci-plugin", havingValue = "CredissuerVCIssuancePlugin")
@Component
@Slf4j
public class CredissuerVCIssuancePlugin implements VCIssuancePlugin {

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
    private RestTemplate restTemplate;

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
            individualId = (String) identityDetails.get("sub");
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

    @Override
    public VCResult<String> getVerifiableCredential(VCRequestDto vcRequestDto, String holderId, Map<String, Object> identityDetails) throws VCIExchangeException {
        throw new VCIExchangeException(ErrorConstants.NOT_IMPLEMENTED);
    }

}
