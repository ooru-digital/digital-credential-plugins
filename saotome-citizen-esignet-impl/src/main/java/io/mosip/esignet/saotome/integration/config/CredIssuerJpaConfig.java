package io.mosip.esignet.saotome.integration.config;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@Configuration
@EnableJpaRepositories(basePackages = "io.mosip.esignet.saotome.integration.repository")
@EntityScan(basePackages = "io.mosip.esignet.saotome.integration.entity")
public class CredIssuerJpaConfig {
}
