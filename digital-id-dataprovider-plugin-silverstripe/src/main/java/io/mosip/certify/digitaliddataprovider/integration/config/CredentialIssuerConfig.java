package io.mosip.certify.digitaliddataprovider.integration.config;

import lombok.Data;

@Data
public class CredentialIssuerConfig {
    private String orgCode;
    private String email;
    private String templateId;
}
