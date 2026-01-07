package io.mosip.esignet.saotome.integration.entity;

import lombok.*;
import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "kyc_auth", schema = "esignet")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class KycAuth {

    @Id
    @Column(name = "kyc_token")
    private String kycToken;

    @Column(name = "individual_id")
    private String individualId;

    @Column(name = "partner_specific_user_token")
    private String partnerSpecificUserToken;

    @Column(name = "response_time")
    private LocalDateTime responseTime;

    @Column(name = "transaction_id")
    private String transactionId;

    @Column(name = "validity")
    private Integer validity;
}
