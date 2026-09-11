# saotome-citizen-esignet-integration-impl

## About
Implementation for all the interfaces defined in esignet-integration-api. This library is built as a wrapper for the SaoTome citizen portal service.

## Configurations required in `esignet-default.properties`

```properties
# Package scan base for integration
mosip.esignet.integration.scan-base-package=io.mosip.esignet.saotome.integration

# Plugin beans for SaoTome
mosip.esignet.integration.authenticator=SaoTomeCitizensAuthenticationService
mosip.esignet.integration.key-binder=NoOpKeyBinder
mosip.esignet.integration.audit-plugin=LoggerAuditService
mosip.esignet.integration.captcha-validator=GoogleRecaptchaValidatorService

# -------------------- SaoTome Authenticator Configuration -------------------- #
mosip.esignet.authenticator.saotome.send-otp-url=https://<saotome-citizen-api>/send-otp
mosip.esignet.authenticator.saotome.verify-otp-url=https://<saotome-citizen-api>/verify-otp
mosip.esignet.authenticator.saotome.citizen-details-url=https://<saotome-citizen-api>/citizen/
mosip.esignet.mock.authenticator.ida.otp-channels=email,sms
mosip.esignet.authenticator.saotome.encrypt-kyc=true

# Add "bindingtransaction" cache name in mosip.esignet.cache.names property if needed