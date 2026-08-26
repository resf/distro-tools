#!/usr/bin/env python3
"""
Metrics for distro-tools#73: CVEs affecting supported Rocky products that have
neither an RLSA nor a cve_product_statuses row.

Usage (on db1 or any host with DB access):

  set -a; source ~/apollo/.env; set +a
  export DB_USER=apollo DB_HOST=127.0.0.1 PGPASSWORD=...
  psql -h "$DB_HOST" -U "$DB_USER" -d apollo2production -f scripts/cve73_gap_metrics.sql

Or run the SQL embedded below via psql -c.
"""

GAP_SQL = r"""
-- Baseline clone gap
SELECT
  (SELECT count(*) FROM red_hat_advisories WHERE name LIKE 'RHSA-%') AS rhsa,
  (SELECT count(*) FROM advisories WHERE name LIKE 'RLSA-%') AS rlsa,
  (SELECT count(DISTINCT ac.cve) FROM advisory_cves ac
     JOIN advisories a ON a.id = ac.advisory_id WHERE a.name LIKE 'RLSA-%') AS cves_on_rlsa,
  (SELECT count(DISTINCT c.cve) FROM red_hat_advisory_cves c
     WHERE NOT EXISTS (
       SELECT 1 FROM advisory_cves ac
       JOIN advisories a ON a.id = ac.advisory_id
       WHERE a.name LIKE 'RLSA-%' AND ac.cve = c.cve)) AS cves_never_on_rlsa;

-- Status coverage (requires cve_product_statuses migration)
SELECT
  status,
  count(*) AS rows,
  count(DISTINCT cve) AS distinct_cves
FROM cve_product_statuses
GROUP BY status
ORDER BY status;

-- Gap metric: RHSA CVEs on EL8/9/10 with no RLSA and no status row
WITH el_cves AS (
  SELECT DISTINCT c.cve
  FROM red_hat_advisory_cves c
  JOIN red_hat_advisories r ON r.id = c.red_hat_advisory_id
  JOIN red_hat_advisory_affected_products ap ON ap.red_hat_advisory_id = r.id
  WHERE r.name LIKE 'RHSA-%'
    AND ap.major_version IN (8, 9, 10)
),
on_rlsa AS (
  SELECT DISTINCT ac.cve
  FROM advisory_cves ac
  JOIN advisories a ON a.id = ac.advisory_id
  WHERE a.name LIKE 'RLSA-%'
),
has_status AS (
  SELECT DISTINCT cve FROM cve_product_statuses
)
SELECT
  (SELECT count(*) FROM el_cves) AS el8910_rhsa_cves,
  (SELECT count(*) FROM el_cves e WHERE EXISTS (SELECT 1 FROM on_rlsa r WHERE r.cve = e.cve)) AS with_rlsa,
  (SELECT count(*) FROM el_cves e WHERE EXISTS (SELECT 1 FROM has_status s WHERE s.cve = e.cve)) AS with_status,
  (SELECT count(*) FROM el_cves e
     WHERE NOT EXISTS (SELECT 1 FROM on_rlsa r WHERE r.cve = e.cve)
       AND NOT EXISTS (SELECT 1 FROM has_status s WHERE s.cve = e.cve)
  ) AS neither_rlsa_nor_status;
"""

if __name__ == "__main__":
    print(GAP_SQL)
