package io.mosip.esignet.credissuer.integration.repository;

import io.mosip.esignet.credissuer.integration.entity.KycAuth;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface KycAuthRepository extends JpaRepository<KycAuth, String> {
    KycAuth findByKycToken(String kycToken);
}
