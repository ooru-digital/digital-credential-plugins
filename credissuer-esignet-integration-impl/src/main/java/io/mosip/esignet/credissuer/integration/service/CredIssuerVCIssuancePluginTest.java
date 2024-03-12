package io.mosip.esignet.credissuer.integration.service;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.esignet.api.dto.VCRequestDto;
import io.mosip.esignet.api.dto.VCResult;
import io.mosip.esignet.api.exception.VCIExchangeException;

import java.util.HashMap;
import java.util.Map;

public class CredIssuerVCIssuancePluginTest {

    public static void main(String[] args) {
        try {
            CredIssuerVCIssuancePlugin vciIssuancePlugin = new CredIssuerVCIssuancePlugin();
            vciIssuancePlugin.initialize(); // You may want to call initialize method before testing

            // You can provide the required parameters for testing
            VCRequestDto vcRequestDto = new VCRequestDto(); // Set your VCRequestDto data
            String holderId = "exampleHolderId";
            Map<String, Object> identityDetails = new HashMap<>(); // Set your identityDetails data

            // Call the method to fetch the verifiable credential with linked data proof
            VCResult<JsonLDObject> vcResult = vciIssuancePlugin.getVerifiableCredentialWithLinkedDataProof(vcRequestDto, holderId, identityDetails);

            // Process the result or print it for testing purposes
            if (vcResult != null && vcResult.getCredential() != null) {
                System.out.println("Verifiable Credential with Linked Data Proof:");
                System.out.println(vcResult.getCredential().toString());
            } else {
                System.out.println("Failed to fetch Verifiable Credential with Linked Data Proof");
            }
        } catch (VCIExchangeException e) {
            System.err.println("Error during testing: " + e.getMessage());
        }
    }
}

