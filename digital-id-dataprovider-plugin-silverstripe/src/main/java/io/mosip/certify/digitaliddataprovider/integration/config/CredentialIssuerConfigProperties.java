package io.mosip.certify.digitaliddataprovider.integration.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import java.util.HashMap;
import java.util.Map;

@Data
@Component
@ConfigurationProperties(prefix = "credential.issuer")
public class CredentialIssuerConfigProperties {

    // key = credential type (e.g., IdCard13)
    private Map<String, CredentialIssuerConfig> configs = new HashMap<>();
}
