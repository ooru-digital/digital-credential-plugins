/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.esignet.credissuer.integration.service;


import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.esignet.api.exception.VCIExchangeException;
import io.mosip.esignet.api.util.ErrorConstants;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.signature.dto.JWTSignatureRequestDto;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.service.SignatureService;
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
import foundation.identity.jsonld.JsonLDObject;
import io.mosip.esignet.api.dto.VCRequestDto;
import io.mosip.esignet.api.dto.VCResult;
import io.mosip.esignet.api.spi.VCIssuancePlugin;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import java.security.GeneralSecurityException;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.ConfigurableDocumentLoader;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import java.net.URI;




import javax.annotation.PostConstruct;


@ConditionalOnProperty(value = "mosip.esignet.integration.vci-plugin", havingValue = "CredIssuerVCIssuancePlugin")
@Component
@Slf4j
public class CredIssuerVCIssuancePlugin implements VCIssuancePlugin {

    private static final String CREDENTIAL_TYPE_PROPERTY_PREFIX ="mosip.esignet.vciplugin.credissuer.credential-type";

    private static final String LINKED_DATA_PROOF_VC_FORMAT ="ldp_vc";
    public static final String UTC_DATETIME_PATTERN = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";

    private static final String TEMPLATE_URL = "template-url";

    private static final String REGISTRY_GET_URL = "registry-get-url";

    private static final String CRED_SCHEMA_ID = "cred-schema-id";

    private static final String CRED_SCHEMA_VESRION = "cred-schema-version";

    private static final String STATIC_VALUE_MAP_ISSUER_ID = "static-value-map.issuerId";

    private static final String CREDENTIAL_OBJECT_KEY = "credential";

    public static final String OIDC_SERVICE_APP_ID = "OIDC_SERVICE";

    private ConfigurableDocumentLoader confDocumentLoader = null;

    @Value("${mosip.esignet.mock.vciplugin.verification-method}")
    private String verificationMethod;

    @Autowired
    Environment env;

    @Autowired
    ObjectMapper mapper;

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private SignatureService signatureService;

    @Value("${mosip.esignet.vciplugin.credissuer.issue-credential-url}")
    String issueCredentialUrl;

    @Value("#{'${mosip.esignet.vciplugin.credissuer.supported-credential-types}'.split(',')}")
    List<String> supportedCredentialTypes;

    private final Map<String, Template> credentialTypeTemplates = new HashMap<>();

    private final Map<String,Map<String,String>> credentialTypeConfigMap = new HashMap<>();

    private VelocityEngine vEngine;


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
        log.info("inside>>>>>>>>>>>>>>");
        try {
            VCResult vcResult = new VCResult();
            //vcJsonLdObject = buildDummyJsonLDWithLDProof(holderId);
            Map<String,Object> vcResponseMap = fetchCredential("https://run.mocky.io/v3/a55b2c6d-a93a-4337-946f-0f608f16f0ac");
            vcJsonLdObject = JsonLDObject.fromJsonObject((Map<String, Object>)vcResponseMap.get(CREDENTIAL_OBJECT_KEY));
            vcResult.setCredential(vcJsonLdObject);
            vcResult.setFormat("ldp_vc");
            return vcResult;
        } catch (Exception e) {
            log.error("Failed to build credissuer response", e);
        }
        throw new VCIExchangeException();
    }

    /*private JsonLDObject buildDummyJsonLDWithLDProof(String holderId)
            throws IOException, GeneralSecurityException, JsonLDException, URISyntaxException {
        Map<String, Object> formattedMap = new HashMap<>();
        formattedMap.put("id", holderId);
        formattedMap.put("name", "John Doe");
        formattedMap.put("email", "john.doe@mail.com");
        formattedMap.put("gender", "Male");

        Map<String, Object> verCredJsonObject = new HashMap<>();
        verCredJsonObject.put("@context", Arrays.asList("https://www.w3.org/2018/credentials/v1", "https://schema.org/"));
        verCredJsonObject.put("type", Arrays.asList("VerifiableCredential", "Person"));
        verCredJsonObject.put("id", "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5");
        verCredJsonObject.put("issuer", "did:example:123456789");
        verCredJsonObject.put("issuanceDate", getUTCDateTime());
        verCredJsonObject.put("credentialSubject", formattedMap);

        JsonLDObject vcJsonLdObject = JsonLDObject.fromJsonObject(verCredJsonObject);
        vcJsonLdObject.setDocumentLoader(confDocumentLoader);
        // vc proof
        Date created = Date
                .from(LocalDateTime
                        .parse((String) verCredJsonObject.get("issuanceDate"),
                                DateTimeFormatter.ofPattern(UTC_DATETIME_PATTERN))
                        .atZone(ZoneId.systemDefault()).toInstant());
        LdProof vcLdProof = LdProof.builder().defaultContexts(false).defaultTypes(false).type("RsaSignature2018")
                .created(created).proofPurpose("assertionMethod")
                .verificationMethod(URI.create(verificationMethod))
                .build();

        URDNA2015Canonicalizer canonicalizer = new URDNA2015Canonicalizer();
        byte[] vcSignBytes = canonicalizer.canonicalize(vcLdProof, vcJsonLdObject);
        String vcEncodedData = CryptoUtil.encodeToURLSafeBase64(vcSignBytes);

        JWTSignatureRequestDto jwtSignatureRequestDto = new JWTSignatureRequestDto();
        jwtSignatureRequestDto.setApplicationId(OIDC_SERVICE_APP_ID);
        jwtSignatureRequestDto.setReferenceId("");
        jwtSignatureRequestDto.setIncludePayload(false);
        jwtSignatureRequestDto.setIncludeCertificate(true);
        jwtSignatureRequestDto.setIncludeCertHash(true);
        jwtSignatureRequestDto.setDataToSign(vcEncodedData);
        JWTSignatureResponseDto responseDto = signatureService.jwtSign(jwtSignatureRequestDto);
        LdProof ldProofWithJWS = LdProof.builder().base(vcLdProof).defaultContexts(false)
                .jws(responseDto.getJwtSignedData()).build();
        ldProofWithJWS.addToJsonLDObject(vcJsonLdObject);
        return vcJsonLdObject;
    }*/



    @Override
    public VCResult<String> getVerifiableCredential(VCRequestDto vcRequestDto, String holderId, Map<String, Object> identityDetails) throws VCIExchangeException {

        throw new VCIExchangeException(ErrorConstants.NOT_IMPLEMENTED);
    }

    private Map<String,Object> fetchCredential(String entityUrl) throws VCIExchangeException {
        RequestEntity requestEntity = RequestEntity
                .get(UriComponentsBuilder.fromUriString(entityUrl).build().toUri()).build();
        ResponseEntity<Map<String,Object>> responseEntity = restTemplate.exchange(requestEntity,
                new ParameterizedTypeReference<Map<String,Object>>() {});
        if (responseEntity.getStatusCode().is2xxSuccessful() && responseEntity.getBody() != null) {
            return responseEntity.getBody();
        }else {
            log.error("Credissuer service is not running. Status Code: " , responseEntity.getStatusCode());
            throw new VCIExchangeException(ErrorConstants.VCI_EXCHANGE_FAILED);
        }
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
        //validateAndLoadProperty(CREDENTIAL_TYPE_PROPERTY_PREFIX + "." + credentialType + "." + TEMPLATE_URL,TEMPLATE_URL,configMap);
        validateAndLoadProperty(CREDENTIAL_TYPE_PROPERTY_PREFIX + "." + credentialType + "." + REGISTRY_GET_URL,REGISTRY_GET_URL,configMap);
        validateAndLoadProperty(CREDENTIAL_TYPE_PROPERTY_PREFIX + "." + credentialType + "." + CRED_SCHEMA_ID,CRED_SCHEMA_ID,configMap);
        validateAndLoadProperty(CREDENTIAL_TYPE_PROPERTY_PREFIX + "." + credentialType + "." + CRED_SCHEMA_VESRION,CRED_SCHEMA_VESRION,configMap);
        validateAndLoadProperty(CREDENTIAL_TYPE_PROPERTY_PREFIX + "." + credentialType + "." + STATIC_VALUE_MAP_ISSUER_ID,STATIC_VALUE_MAP_ISSUER_ID,configMap);

        //String templateUrl = env.getProperty(CREDENTIAL_TYPE_PROPERTY_PREFIX +"." + credentialType + "." + TEMPLATE_URL);
        //validateAndCacheTemplate(templateUrl,credentialType);
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

    /*private void validateAndCacheTemplate(String templateUrl, String credentialType){
            Template template = vEngine.getTemplate(templateUrl);
            //Todo Validate if all the templates are valid JSON-LD documents
            credentialTypeTemplates.put(credentialType, template);
    }*/

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

    private static String getUTCDateTime() {
        return ZonedDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ofPattern(UTC_DATETIME_PATTERN));
    }

}
