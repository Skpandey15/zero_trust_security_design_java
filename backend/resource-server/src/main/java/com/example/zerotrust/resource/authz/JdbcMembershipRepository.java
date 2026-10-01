package com.example.zerotrust.resource.authz;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Reads membership from the identity store's {@code subject_tenant_membership}
 * table through a database role that can SELECT that table and nothing else of
 * the identity schema (ADR-SEC-019: a compromised Resource Server must not hold
 * the keys to the identity database).
 *
 * <p>A row whose role this service does not recognise grants NOTHING: an
 * unknown role string is never read as a default permission.
 */
@Repository
public class JdbcMembershipRepository implements MembershipRepository {

    /** The table name is configuration, but it is concatenated into SQL, so it is validated hard. */
    private static final Pattern SAFE_TABLE = Pattern.compile("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)?");

    private final JdbcTemplate jdbc;
    private final String table;
    private final String tenantsTable;

    public JdbcMembershipRepository(JdbcTemplate jdbc,
                                    @Value("${app.membership.table:public.subject_tenant_membership}") String table,
                                    @Value("${app.membership.tenants-table:public.tenants}") String tenantsTable) {
        for (String t : new String[] {table, tenantsTable}) {
            if (!SAFE_TABLE.matcher(t).matches()) {
                throw new IllegalArgumentException("a membership table setting is not a plain table name: " + t);
            }
        }
        this.jdbc = jdbc;
        this.table = table;
        this.tenantsTable = tenantsTable;
    }

    @Override
    public Optional<TenantRole> roleOf(long uid, String tenantId) {
        return jdbc.query("SELECT role FROM " + table + " WHERE user_id = ? AND tenant_id = ?",
                        (rs, i) -> rs.getString(1), uid, tenantId)
                .stream().findFirst().flatMap(TenantRole::parse);
    }

    @Override
    public Map<String, TenantRole> tenantsOf(long uid) {
        Map<String, TenantRole> result = new HashMap<>();
        jdbc.query("SELECT tenant_id, role FROM " + table + " WHERE user_id = ?", rs -> {
            String tenant = rs.getString(1);
            TenantRole.parse(rs.getString(2)).ifPresent(r -> result.put(tenant, r));
        }, uid);
        return result;
    }

    @Override
    public List<TenantInfo> describe(long uid) {
        return jdbc.query("SELECT m.tenant_id, t.name, m.role FROM " + table + " m JOIN " + tenantsTable
                        + " t ON t.id = m.tenant_id WHERE m.user_id = ? AND t.status = 'ACTIVE' ORDER BY t.name",
                        (rs, i) -> {
                            String id = rs.getString(1);
                            String name = rs.getString(2);
                            return TenantRole.parse(rs.getString(3)).map(r -> new TenantInfo(id, name, r)).orElse(null);
                        },
                        uid)
                .stream().filter(java.util.Objects::nonNull).toList();
    }
}
