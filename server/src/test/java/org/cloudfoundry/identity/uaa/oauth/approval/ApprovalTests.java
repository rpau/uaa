package org.cloudfoundry.identity.uaa.oauth.approval;

import org.cloudfoundry.identity.uaa.approval.Approval;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ApprovalTests {

    @Test
    void testHashCode() {
        assertThat(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(500))
                .setStatus(Approval.ApprovalStatus.DENIED).hashCode()).isEqualTo(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(100))
                .setStatus(Approval.ApprovalStatus.DENIED).hashCode());
        assertThat(new Approval()
                .setUserId("u1")
                .setClientId("c2")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(100))
                .setStatus(Approval.ApprovalStatus.DENIED).hashCode()).isNotEqualTo(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(100))
                .setStatus(Approval.ApprovalStatus.DENIED).hashCode());
        assertThat(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s2")
                .setExpiresAt(Approval.timeFromNow(100))
                .setStatus(Approval.ApprovalStatus.DENIED).hashCode()).isNotEqualTo(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(100))
                .setStatus(Approval.ApprovalStatus.DENIED).hashCode());
        assertThat(new Approval()
                .setUserId("u2")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(100))
                .setStatus(Approval.ApprovalStatus.DENIED).hashCode()).isNotEqualTo(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(100))
                .setStatus(Approval.ApprovalStatus.DENIED).hashCode());
        assertThat(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(100))
                .setStatus(Approval.ApprovalStatus.APPROVED).hashCode()).isNotEqualTo(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(100))
                .setStatus(Approval.ApprovalStatus.DENIED).hashCode());
    }

    @Test
    void equals() {
        assertThat(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(500))
                .setStatus(Approval.ApprovalStatus.DENIED)).isEqualTo(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(100))
                .setStatus(Approval.ApprovalStatus.DENIED));
        assertThat(new Approval()
                .setUserId("u1")
                .setClientId("c2")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(100))
                .setStatus(Approval.ApprovalStatus.DENIED)).isNotEqualTo(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(100))
                .setStatus(Approval.ApprovalStatus.DENIED));
        assertThat(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s2")
                .setExpiresAt(Approval.timeFromNow(100))
                .setStatus(Approval.ApprovalStatus.DENIED)).isNotEqualTo(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(100))
                .setStatus(Approval.ApprovalStatus.DENIED));
        assertThat(new Approval()
                .setUserId("u2")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(100))
                .setStatus(Approval.ApprovalStatus.DENIED)).isNotEqualTo(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(100))
                .setStatus(Approval.ApprovalStatus.DENIED));
        assertThat(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(100))
                .setStatus(Approval.ApprovalStatus.APPROVED)).isNotEqualTo(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(100))
                .setStatus(Approval.ApprovalStatus.DENIED));

        List<Approval> approvals = Arrays.asList(new Approval()
                        .setUserId("u1")
                        .setClientId("c1")
                        .setScope("s1")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.APPROVED),
                new Approval()
                        .setUserId("u1")
                        .setClientId("c1")
                        .setScope("s2")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.APPROVED),
                new Approval()
                        .setUserId("u1")
                        .setClientId("c1")
                        .setScope("s3")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.APPROVED),
                new Approval()
                        .setUserId("u1")
                        .setClientId("c2")
                        .setScope("s1")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.APPROVED),
                new Approval()
                        .setUserId("u1")
                        .setClientId("c2")
                        .setScope("s2")
                        .setExpiresAt(Approval.timeFromNow(100))
                        .setStatus(Approval.ApprovalStatus.DENIED)
        );
        assertThat(approvals.contains(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(100))
                .setStatus(Approval.ApprovalStatus.APPROVED))).isTrue();
        assertThat(approvals.contains(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(100))
                .setStatus(Approval.ApprovalStatus.DENIED))).isFalse();
    }

    @Test
    void expiry() {
        int thirtyMinutes = 30 * 60 * 1000;
        assertThat(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(thirtyMinutes))
                .setStatus(Approval.ApprovalStatus.APPROVED).isActiveAsOf(new Date())).isTrue();
        int expiresIn = -1;
        assertThat(new Approval()
                .setUserId("u1")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(expiresIn))
                .setStatus(Approval.ApprovalStatus.APPROVED).isActiveAsOf(new Date())).isFalse();
    }
}
