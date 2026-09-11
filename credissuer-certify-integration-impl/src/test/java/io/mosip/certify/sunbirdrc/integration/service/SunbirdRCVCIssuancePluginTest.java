package io.mosip.certify.sunbirdrc.integration.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.exception.VCIExchangeException;
import io.mosip.certify.api.util.ErrorConstants;
import org.apache.velocity.Template;
import org.apache.velocity.app.VelocityEngine;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RunWith(MockitoJUnitRunner.class)
@SpringBootTest
public class SunbirdRCVCIssuancePluginTest {

    @Mock
    private RestTemplate restTemplate;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private Environment environment;

    @InjectMocks
    private CredissuerVCIssuancePlugin sunbirdRCVCIssuancePlugin;

    private VelocityEngine velocityEngine;

    private Map<String,Map<String,String>> credentialTypeConfigMap;

    private Map<String,Template> credentialTypeTemplatesMap;

    Template template;

    @Before
    public void init(){
        velocityEngine=new VelocityEngine();
        velocityEngine.setProperty("resource.loader", "class");
        velocityEngine.setProperty("class.resource.loader.class", "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
        template=velocityEngine.getTemplate("InsuranceCredential.json");

        credentialTypeTemplatesMap=new HashMap<>();
        credentialTypeTemplatesMap.put("InsuranceCredential",template);

        credentialTypeConfigMap=new HashMap<>();
        Map<String,String> credentialMap=new HashMap<>();
        credentialMap.put("registry-get-url","url");
        credentialTypeConfigMap.put("InsuranceCredential",credentialMap);

        ReflectionTestUtils.setField(sunbirdRCVCIssuancePlugin,"supportedCredentialTypes",List.of("InsuranceCredential"));
        ReflectionTestUtils.setField(sunbirdRCVCIssuancePlugin,"credentialTypeTemplates",credentialTypeTemplatesMap);
        ReflectionTestUtils.setField(sunbirdRCVCIssuancePlugin,"credentialTypeConfigMap",credentialTypeConfigMap);
    }

    @Test
    public void getVerifiableCredentialWithLinkedDataProof_ValidDetails_ThenPass() throws VCIExchangeException, JsonProcessingException {
        ReflectionTestUtils.setField(sunbirdRCVCIssuancePlugin,"issueCredentialUrl","https://test.com");
        VCRequestDto vcRequestDto=new VCRequestDto();
        List<String> contextList=List.of("https://www.w3.org/2018/credentials/examples/v1","https://www.w3.org/2018/credentials/v1");
        vcRequestDto.setContext(contextList);
        vcRequestDto.setFormat("test");
        List<String> types=new ArrayList<>();
        types.add("VerifiableCredential");
        types.add("InsuranceCredential");
        vcRequestDto.setType(types);

        Map<String,Object> identityMap=new HashMap<>();
        identityMap.put("sub","osid");

        Map<String,Object> responseMap=Map.of("policyNumber","654321","dob","654321");

        ResponseEntity<Map<String,Object>>  responseEntity = new ResponseEntity(responseMap, HttpStatus.OK);
        Mockito.when(restTemplate.exchange(
                Mockito.any(RequestEntity.class),
                Mockito.eq(new ParameterizedTypeReference<Map<String,Object>>() {}))).thenReturn(responseEntity);

        Map<String,Object> mockChallengMap=new HashMap<>();
        Map<String,Object> credentialSubjectMap=new HashMap<>();
        mockChallengMap.put("@context",List.of("https://www.w3.org/2018/credentials/examples/v1","https://www.w3.org/2018/credentials/v1"));
        mockChallengMap.put("credentialSubject",credentialSubjectMap);
        Mockito.when(objectMapper.readValue(Mockito.anyString(),Mockito.eq(Map.class))).thenReturn(mockChallengMap);

        VCResult<JsonLDObject> result= sunbirdRCVCIssuancePlugin.getVerifiableCredentialWithLinkedDataProof(vcRequestDto,"holderId",identityMap);
        Assert.assertNotNull(result);
    }

    @Test
    public void getVerifiableCredentialWithLinkedDataProof_WithPsutDetails_ThenPass() throws VCIExchangeException, JsonProcessingException {
        ReflectionTestUtils.setField(sunbirdRCVCIssuancePlugin,"issueCredentialUrl","https://test.com");
        ReflectionTestUtils.setField(sunbirdRCVCIssuancePlugin,"enablePSUTBasedRegistrySearch",true);

        Map<String,Map<String,String>> credentialTypeConfigMap = new HashMap<>();
        credentialTypeConfigMap.put("InsuranceCredential",Map.of("registry-search-url","test"));

        ReflectionTestUtils.setField(sunbirdRCVCIssuancePlugin,"credentialTypeConfigMap",credentialTypeConfigMap);
        VCRequestDto vcRequestDto=new VCRequestDto();
        List<String> contextList=List.of("https://www.w3.org/2018/credentials/examples/v1","https://www.w3.org/2018/credentials/v1");
        vcRequestDto.setContext(contextList);
        vcRequestDto.setFormat("test");
        List<String> types=new ArrayList<>();
        types.add("VerifiableCredential");
        types.add("InsuranceCredential");
        vcRequestDto.setType(types);

        Map<String,Object> identityMap=new HashMap<>();
        identityMap.put("sub","osid");

        Map<String,Object> responseMap=Map.of("policyNumber","654321","dob","654321");
        List<Map<String,Object>> responseList=List.of(responseMap);

        ResponseEntity<List<Map<String,Object>>>  responseEntity = new ResponseEntity(responseList, HttpStatus.OK);
        Mockito.when(restTemplate.exchange(
                Mockito.any(RequestEntity.class),
                Mockito.eq(new ParameterizedTypeReference<List<Map<String,Object>>>() {}))).thenReturn(responseEntity);

        Map<String,Object> vcResponseMap=Map.of("policyNumber","654321","dob","654321");

        ResponseEntity<Map<String,Object>>  VcResponseEntity = new ResponseEntity(vcResponseMap, HttpStatus.OK);
        Mockito.when(restTemplate.exchange(
                Mockito.any(RequestEntity.class),
                Mockito.eq(new ParameterizedTypeReference<Map<String,Object>>() {}))).thenReturn(VcResponseEntity);


        Map<String,Object> mockChallengMap=new HashMap<>();
        Map<String,Object> credentialSubjectMap=new HashMap<>();
        mockChallengMap.put("@context",List.of("https://www.w3.org/2018/credentials/examples/v1","https://www.w3.org/2018/credentials/v1"));
        mockChallengMap.put("credentialSubject",credentialSubjectMap);
        Mockito.when(objectMapper.readValue(Mockito.anyString(),Mockito.eq(Map.class))).thenReturn(mockChallengMap);

        VCResult<JsonLDObject> result= sunbirdRCVCIssuancePlugin.getVerifiableCredentialWithLinkedDataProof(vcRequestDto,"holderId",identityMap);
        Assert.assertNotNull(result);
    }

    @Test
    public void getVerifiableCredentialWithLinkedDataProof_InValidRequest_ThenFail() {
        try{
            sunbirdRCVCIssuancePlugin.getVerifiableCredentialWithLinkedDataProof(null,"holderId",null);
        }catch (VCIExchangeException e){
            Assert.assertEquals(e.getErrorCode(), ErrorConstants.VCI_EXCHANGE_FAILED);
        }
    }

    @Test
    public void getVerifiableCredentialWithLinkedDataProof_With_EmptyTypes_ThenFail()  {
        try{
            VCRequestDto vcRequestDto=new VCRequestDto();
            List<String> types=new ArrayList<>();
            types.add("InsuranceCredential");
            vcRequestDto.setType(types);
            sunbirdRCVCIssuancePlugin.getVerifiableCredentialWithLinkedDataProof(vcRequestDto,"holderId",null);
        }catch (VCIExchangeException e){
            Assert.assertEquals(e.getErrorCode(), ErrorConstants.VCI_EXCHANGE_FAILED);
        }
    }

    @Test
    public void getVerifiableCredentialWithLinkedDataProof_InValidSupportedCredential_ThenFail()  {
        try{
            VCRequestDto vcRequestDto=new VCRequestDto();
            List<String> types=new ArrayList<>();
            types.add("VerifiableCredential");
            types.add("Credential");
            vcRequestDto.setType(types);
            sunbirdRCVCIssuancePlugin.getVerifiableCredentialWithLinkedDataProof(vcRequestDto,"holderId",null);
        }catch (VCIExchangeException e){
            Assert.assertEquals(e.getErrorCode(), ErrorConstants.VCI_EXCHANGE_FAILED);
        }
    }

    @Test
    public void getVerifiableCredentialWithLinkedDataProof_InValidRegistryObject_ThenFail() throws JsonProcessingException {
        ReflectionTestUtils.setField(sunbirdRCVCIssuancePlugin,"issueCredentialUrl","https://test.com");
        VCRequestDto vcRequestDto=new VCRequestDto();
        List<String> contextList=List.of("https://www.w3.org/2018/credentials/examples/v1","https://www.w3.org/2018/credentials/v1");
        vcRequestDto.setContext(contextList);
        vcRequestDto.setFormat("test");
        List<String> types=new ArrayList<>();
        types.add("VerifiableCredential");
        types.add("InsuranceCredential");
        vcRequestDto.setType(types);

        Map<String,Object> identityMap=new HashMap<>();
        identityMap.put("sub","osid");

        Map<String,Object> responseMap=Map.of("policyNumber","654321","dob","654321");
        ResponseEntity<Map<String,Object>>  responseEntity = new ResponseEntity(responseMap, HttpStatus.FORBIDDEN);
        Mockito.when(restTemplate.exchange(
                Mockito.any(RequestEntity.class),
                Mockito.eq(new ParameterizedTypeReference<Map<String,Object>>() {}))).thenReturn(responseEntity);

        Map<String,Object> mockChallengMap=new HashMap<>();
        Map<String,Object> credentialSubjectMap=new HashMap<>();
        mockChallengMap.put("@context",List.of("https://www.w3.org/2018/credentials/examples/v1","https://www.w3.org/2018/credentials/v1"));
        mockChallengMap.put("credentialSubject",credentialSubjectMap);
        Mockito.when(objectMapper.readValue(Mockito.anyString(),Mockito.eq(Map.class))).thenReturn(mockChallengMap);

        try{
            sunbirdRCVCIssuancePlugin.getVerifiableCredentialWithLinkedDataProof(vcRequestDto,"holderId",identityMap);
        }catch (VCIExchangeException e){
            Assert.assertEquals(e.getErrorCode(), ErrorConstants.VCI_EXCHANGE_FAILED);
        }
    }

    @Test
    public void getVerifiableCredentialWithLinkedDataProof_InValidCredentialDetails_ThenFail() throws JsonProcessingException {

        VCRequestDto vcRequestDto=new VCRequestDto();
        List<String> contextList=List.of("https://www.w3.org/2018/credentials/examples/v1","https://www.w3.org/2018/credentials/v1");
        vcRequestDto.setContext(contextList);
        vcRequestDto.setFormat("test");
        List<String> types=new ArrayList<>();
        types.add("VerifiableCredential");
        types.add("InsuranceCredential");
        vcRequestDto.setType(types);

        Map<String,Object> identityMap=new HashMap<>();
        identityMap.put("sub","osid");

        Map<String,Object> responseMap=Map.of("policyNumber","654321","dob","654321");
        ResponseEntity<Map<String,Object>>  responseEntity = new ResponseEntity(responseMap, HttpStatus.OK);
        Mockito.when(restTemplate.exchange(
                Mockito.any(RequestEntity.class),
                Mockito.eq(new ParameterizedTypeReference<Map<String,Object>>() {}))).thenReturn(responseEntity);

        Map<String,Object> mockChallengMap=new HashMap<>();
        Map<String,Object> credentialSubjectMap=new HashMap<>();
        mockChallengMap.put("@context",List.of("https://www.w3.org/2018/credentials/examples/v1","https://www.w3.org/2018/credentials/v1"));
        mockChallengMap.put("credentialSubject",credentialSubjectMap);
        Mockito.when(objectMapper.readValue(Mockito.anyString(),Mockito.eq(Map.class))).thenReturn(mockChallengMap);

        try{
            sunbirdRCVCIssuancePlugin.getVerifiableCredentialWithLinkedDataProof(vcRequestDto,"holderId",identityMap);
        }catch (VCIExchangeException e){
            Assert.assertEquals(e.getErrorCode(), ErrorConstants.VCI_EXCHANGE_FAILED);
        }
    }

    @Test
    public void initialize_ValidDetails_ThenPass() throws VCIExchangeException {
        URL credentialUrl = getClass().getClassLoader().getResource("InsuranceCredential.json");
        if (credentialUrl == null) {
            throw new VCIExchangeException("InsuranceCredential.json not found in classpath");
        }
        String credentialPath = credentialUrl.toString();
        Mockito.when(environment.getProperty(Mockito.anyString())).thenReturn(credentialPath);
        sunbirdRCVCIssuancePlugin.initialize();
    }


    @Test
    public void initialize_InValidPropertyDetails_ThenPass()  {

        Mockito.when(environment.getProperty(Mockito.anyString())).thenReturn(null);
        try{
            sunbirdRCVCIssuancePlugin.initialize();
        }catch (VCIExchangeException e){
            Assert.assertEquals("Property mosip.certify.vciplugin.sunbird-rc.credential-type.InsuranceCredential.template-url is not set Properly.", e.getMessage());
        }
    }

    @Test
    public void getVerifiableCredentialWithLinkedDataProof_InvalidContextURL_ThenFail() throws  JsonProcessingException {
        ReflectionTestUtils.setField(sunbirdRCVCIssuancePlugin,"issueCredentialUrl","https://test.com");
        VCRequestDto vcRequestDto=new VCRequestDto();
        List<String> contextList=List.of("https://www.w3.org/2018/credentials/examples/v1","https://www.w3.org/2018/credentials/v1");
        vcRequestDto.setContext(contextList);
        vcRequestDto.setFormat("test");
        List<String> types=new ArrayList<>();
        types.add("VerifiableCredential");
        types.add("InsuranceCredential");
        vcRequestDto.setType(types);

        Map<String,Object> identityMap=new HashMap<>();
        identityMap.put("sub","osid");
        Map<String,Object> mockChallengMap=new HashMap<>();

        Map<String,Object> credentialSubjectMap=new HashMap<>();
        mockChallengMap.put("@context",List.of("https://www.w3.org/2018/examples/v1","https://www.w3.org/2018/credentials/v1"));
        mockChallengMap.put("credentialSubject",credentialSubjectMap);
        Mockito.when(objectMapper.readValue(Mockito.anyString(),Mockito.eq(Map.class))).thenReturn(mockChallengMap);

        try{
            sunbirdRCVCIssuancePlugin.getVerifiableCredentialWithLinkedDataProof(vcRequestDto,"holderId",identityMap);
        }catch (VCIExchangeException e){
            Assert.assertEquals(e.getErrorCode(), ErrorConstants.VCI_EXCHANGE_FAILED);
        }
    }

    @Test
    public void getVerifiableCredentialWithLinkedDataProof_InvalidTemplate_ThenFail() throws  JsonProcessingException {
        ReflectionTestUtils.setField(sunbirdRCVCIssuancePlugin,"issueCredentialUrl","https://test.com");
        VCRequestDto vcRequestDto=new VCRequestDto();
        List<String> contextList=List.of("https://www.w3.org/2018/credentials/examples/v1","https://www.w3.org/2018/credentials/v1");
        vcRequestDto.setContext(contextList);
        vcRequestDto.setFormat("test");
        List<String> types=new ArrayList<>();
        types.add("VerifiableCredential");
        types.add("InsuranceCredential");
        vcRequestDto.setType(types);

        Map<String,Object> identityMap=new HashMap<>();
        identityMap.put("sub","osid");

        Mockito.when(objectMapper.readValue(Mockito.anyString(),Mockito.eq(Map.class))).thenThrow(JsonProcessingException.class);

        try{
            sunbirdRCVCIssuancePlugin.getVerifiableCredentialWithLinkedDataProof(vcRequestDto,"holderId",identityMap);
        }catch (VCIExchangeException e){
            Assert.assertEquals(e.getErrorCode(), ErrorConstants.VCI_EXCHANGE_FAILED);
        }
    }

    @Test
    public void getVerifiableCredential_Test(){
        try{
            sunbirdRCVCIssuancePlugin.getVerifiableCredential(null,"holderId",null);
        }catch (VCIExchangeException e){
            Assert.assertEquals(e.getErrorCode(),ErrorConstants.NOT_IMPLEMENTED);
        }
    }
}
