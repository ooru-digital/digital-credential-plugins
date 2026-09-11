package io.mosip.esignet.saotome.integration.repository;

import io.mosip.esignet.saotome.integration.entity.KycAuth;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface KycAuthRepository extends JpaRepository<KycAuth, String> {
    KycAuth findByKycToken(String kycToken);
}
