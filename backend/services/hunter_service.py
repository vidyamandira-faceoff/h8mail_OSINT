# -*- coding: utf-8 -*-
"""
Hunter Service: Programmatic backend integration for BreachHunter OSINT.
Connects online OSINT breach intelligence APIs (XposedOrNot, LeakLookup, Hunter.io, EmailRep, HIBP)
and local dump databases into a unified, high-performance reconnaissance engine.
"""

import os
import re
import time
import requests
from typing import List, Dict, Any, Optional

from h8mail.utils.classes import target
from h8mail.utils.helpers import check_scylla_online, find_files
from h8mail.utils.localsearch import local_to_targets
from h8mail.utils.localgzipsearch import local_gzip_search

CURRENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_BREACH_FILE = os.path.join(CURRENT_DIR, "data", "sample_breaches.txt")
DEFAULT_LEAKLOOKUP_PUB = "1bf94ff907f68d511de9a610a6ff9263"


class HunterService:
    def __init__(self, default_api_keys: Optional[Dict[str, str]] = None):
        self.api_keys = default_api_keys or {}
        # Ensure default leak-lookup public key is set if not provided
        if "leak-lookup_pub" not in self.api_keys or not self.api_keys["leak-lookup_pub"]:
            self.api_keys["leak-lookup_pub"] = DEFAULT_LEAKLOOKUP_PUB

    def set_api_keys(self, keys: Dict[str, str]):
        self.api_keys.update(keys)

    def extract_targets(self, raw_input: str, query_type: str = "email", loose: bool = False) -> List[str]:
        """
        Parses multi-line or comma/space-separated targets from raw input.
        """
        if not raw_input:
            return []

        # Replace common separators
        cleaned = raw_input.replace(",", "\n").replace(";", "\n")
        lines = [line.strip() for line in cleaned.split("\n") if line.strip()]
        extracted = []

        for line in lines:
            if loose or query_type != "email":
                extracted.append(line)
            else:
                emails = re.findall(r"[\w\.-]+@[\w\.-]+", line)
                if emails:
                    extracted.extend(emails)
                else:
                    extracted.append(line)

        # Deduplicate while preserving order
        seen = set()
        unique = []
        for item in extracted:
            clean = item.strip()
            if clean and clean not in seen:
                seen.add(clean)
                unique.append(clean)
        return unique

    def _query_xposedornot(self, email: str) -> tuple:
        """
        Queries XposedOrNot public free API for breach exposures.
        Returns (found_breaches, status_description)
        """
        found_breaches = []
        try:
            url = f"https://api.xposedornot.com/v1/check-email/{email}"
            headers = {"User-Agent": "BreachHunter-WebOSINT/2.5.6"}
            resp = requests.get(url, headers=headers, timeout=6)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, dict):
                    if "breaches" in data and isinstance(data["breaches"], list):
                        for b in data["breaches"]:
                            if isinstance(b, list):
                                found_breaches.extend([str(item) for item in b])
                            else:
                                found_breaches.append(str(b))
                        if found_breaches:
                            return found_breaches, f"Found ({len(found_breaches)} breaches)"
                    if "Error" in data and "not found" in str(data.get("Error", "")).lower():
                        return [], "Clean (No breaches)"
                return [], "Clean (No breaches)"
            elif resp.status_code == 404:
                return [], "Clean (No breaches)"
            elif resp.status_code == 429:
                return [], "Rate Limited (429)"
            else:
                return [], f"HTTP {resp.status_code}"
        except requests.exceptions.Timeout:
            return [], "Timeout (>6s)"
        except requests.exceptions.ConnectionError:
            return [], "Connection Failed (Check Internet)"
        except Exception as e:
            return [], f"Error ({type(e).__name__})"

    def _query_leaklookup(self, target_str: str, api_key: str) -> tuple:
        """
        Queries Leak-Lookup API for breach references.
        Returns (breaches_list, status_description)
        """
        try:
            url = "https://leak-lookup.com/api/search"
            payload = {"key": api_key, "type": "email_address", "query": target_str}
            headers = {"User-Agent": "BreachHunter-WebOSINT/2.5.6"}
            resp = requests.post(url, data=payload, headers=headers, timeout=6)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, dict):
                    err = str(data.get("error", "false")).lower()
                    if err == "false":
                        msg = data.get("message", [])
                        if isinstance(msg, dict):
                            found = [str(k) for k in msg.keys()]
                        elif isinstance(msg, list):
                            found = [str(x) for x in msg]
                        else:
                            found = []
                        if found:
                            return found, f"Found ({len(found)} breaches)"
                        return [], "Clean (0 breaches)"
                    else:
                        msg_str = str(data.get("message", "API Note"))
                        return [], f"API Note: {msg_str}"
            elif resp.status_code == 429:
                return [], "Rate Limited (429)"
            else:
                return [], f"HTTP {resp.status_code}"
        except requests.exceptions.Timeout:
            return [], "Timeout (>6s)"
        except requests.exceptions.ConnectionError:
            return [], "Connection Failed"
        except Exception as e:
            return [], f"Error ({type(e).__name__})"
        return [], "No response"

    def _query_emailrep(self, email: str, api_key: Optional[str] = None) -> tuple:
        """
        Queries EmailRep.io for email reputation & breach presence.
        Returns (leak_summary_str, status_description)
        """
        headers = {"User-Agent": "BreachHunter-WebOSINT/2.5.6"}
        if api_key:
            headers["Key"] = api_key
        try:
            url = f"https://emailrep.io/{email}"
            resp = requests.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                details = data.get("details", {})
                if details.get("credentials_leaked"):
                    last_seen = details.get("last_seen", "Unknown")
                    breach_count = details.get("data_breaches", 0)
                    summary = f"Exposed in dumps (Breach count: {breach_count}, Last seen: {last_seen})"
                    return summary, "Leak detected"
                return None, "Clean (No breach flag)"
            elif resp.status_code in (401, 403, 429):
                if not api_key:
                    return None, "Requires API Key (Unauthenticated disabled)"
                return None, f"HTTP {resp.status_code} (Key issue)"
            else:
                return None, f"HTTP {resp.status_code}"
        except requests.exceptions.Timeout:
            return None, "Timeout (>5s)"
        except requests.exceptions.ConnectionError:
            return None, "Connection Failed"
        except Exception as e:
            return None, f"Error ({type(e).__name__})"

    def _check_hunterio(self, target_str: str, api_key: Optional[str] = None) -> tuple:
        """
        Checks domain emails on Hunter.io.
        Returns (findings_list, status_description)
        """
        if "@" not in target_str:
            return [], "Skipped (Not an email)"
        domain = target_str.split("@")[1].lower()
        webmail_domains = {
            "gmail.com", "googlemail.com", "yahoo.com", "hotmail.com",
            "outlook.com", "live.com", "icloud.com", "proton.me",
            "protonmail.com", "aol.com", "gmx.com", "mail.com", "zoho.com"
        }
        if domain in webmail_domains:
            return [], f"Skipped (Webmail @{domain} not indexed)"
        if not api_key:
            return [], "Requires API Key (Public endpoint deprecated)"

        try:
            url = f"https://api.hunter.io/v2/email-count?domain={domain}&api_key={api_key}"
            headers = {"User-Agent": "BreachHunter-WebOSINT/2.5.6"}
            resp = requests.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                total = data.get("data", {}).get("total", 0)
                if total > 0:
                    return [f"Hunter.io: {total} related domain emails found for {domain}"], f"Found ({total} related emails)"
                return [], "Clean (0 domain records)"
            elif resp.status_code == 401:
                return [], "Invalid API Key"
            elif resp.status_code == 429:
                return [], "Rate Limited (429)"
            else:
                return [], f"HTTP {resp.status_code}"
        except Exception as e:
            return [], f"Error ({type(e).__name__})"

    def _resolve_path(self, raw_path: str) -> Optional[str]:
        """
        Resolves a raw file/directory path whether absolute or relative.
        """
        if not raw_path:
            return None
        clean_p = raw_path.strip().strip("'\"")
        if os.path.exists(clean_p):
            return os.path.abspath(clean_p)
        project_root = os.path.dirname(CURRENT_DIR)
        cand1 = os.path.join(project_root, clean_p)
        if os.path.exists(cand1):
            return os.path.abspath(cand1)
        cand2 = os.path.join(CURRENT_DIR, clean_p)
        if os.path.exists(cand2):
            return os.path.abspath(cand2)
        return None

    def run_search(
        self,
        targets: List[str],
        query_type: str = "email",
        skip_defaults: bool = False,
        api_keys: Optional[Dict[str, str]] = None,
        local_breach_files: Optional[List[str]] = None,
        local_gzip_files: Optional[List[str]] = None,
        include_sample_db: bool = True,
        hide_passwords: bool = False,
        debug: bool = False,
    ) -> Dict[str, Any]:
        """
        Performs full breach lookup across all online APIs and local databases.
        """
        start_time = time.time()
        active_keys = dict(self.api_keys)
        if api_keys:
            active_keys.update(api_keys)

        processed_targets = []
        engine_audit_map = {}

        for t_str in targets:
            try:
                current_target = target(t_str, debug=debug)
            except Exception:
                current_target = target(t_str)

            audit_list = []

            # 1. Online Public Reconnaissance (when skip_defaults is False)
            if not skip_defaults and query_type == "email":
                # A. XposedOrNot (Free open breach database)
                xon_breaches, xon_status = self._query_xposedornot(t_str)
                if xon_breaches:
                    for b_name in xon_breaches:
                        current_target.data.append(("XPOSEDORNOT", f"Breach Exposure: {b_name}"))
                        current_target.pwned += 1
                audit_list.append({"engine": "XposedOrNot", "status": xon_status})

                # B. Leak-Lookup (Public API)
                lklp_key = active_keys.get("leak-lookup_pub", DEFAULT_LEAKLOOKUP_PUB)
                lklp_breaches, lklp_status = self._query_leaklookup(t_str, lklp_key)
                if lklp_breaches:
                    for b_src in lklp_breaches:
                        current_target.data.append(("LEAKLOOKUP_PUB", b_src))
                        current_target.pwned += 1
                audit_list.append({"engine": "Leak-Lookup", "status": lklp_status})

                # C. Hunter.io (Domain email reconnaissance)
                hunter_key = active_keys.get("hunterio")
                hunter_findings, hunter_status = self._check_hunterio(t_str, hunter_key)
                if hunter_findings:
                    for f in hunter_findings:
                        current_target.data.append(("HUNTER_PUB", f))
                audit_list.append({"engine": "Hunter.io", "status": hunter_status})

                # D. EmailRep.io
                emailrep_key = active_keys.get("emailrep")
                erep_info, erep_status = self._query_emailrep(t_str, emailrep_key)
                if erep_info:
                    current_target.data.append(("EMAILREP", erep_info))
                    current_target.pwned += 1
                audit_list.append({"engine": "EmailRep.io", "status": erep_status})

            elif skip_defaults:
                audit_list.append({"engine": "Online APIs", "status": "Skipped (Offline Mode)"})

            # 2. Configured API Keys Lookups
            if "hibp" in active_keys and active_keys["hibp"] and query_type == "email":
                before_count = len(current_target.data)
                try:
                    current_target.get_hibp3(active_keys["hibp"])
                    if len(current_target.data) > before_count:
                        audit_list.append({"engine": "HaveIBeenPwned", "status": f"Found ({len(current_target.data) - before_count} breaches)"})
                    else:
                        audit_list.append({"engine": "HaveIBeenPwned", "status": "Clean"})
                except Exception as e:
                    audit_list.append({"engine": "HaveIBeenPwned", "status": f"Error: {e}"})
            elif not skip_defaults and query_type == "email":
                audit_list.append({"engine": "HaveIBeenPwned", "status": "Not Configured (Key needed)"})

            if active_keys:
                if "hunterio" in active_keys and active_keys["hunterio"] and query_type == "email":
                    try:
                        current_target.get_hunterio_private(active_keys["hunterio"])
                        audit_list.append({"engine": "Hunter.io (Private)", "status": "Searched"})
                    except Exception:
                        pass

                if "snusbase_token" in active_keys and active_keys["snusbase_token"]:
                    try:
                        url = active_keys.get("snusbase_url", "http://api.snusbase.com/v3/search")
                        current_target.get_snusbase(url, active_keys["snusbase_token"], query_type)
                        audit_list.append({"engine": "Snusbase", "status": "Searched"})
                    except Exception:
                        pass

                if "dehashed_key" in active_keys and active_keys["dehashed_key"] and "dehashed_email" in active_keys:
                    try:
                        current_target.get_dehashed(active_keys["dehashed_email"], active_keys["dehashed_key"], query_type)
                        audit_list.append({"engine": "DeHashed", "status": "Searched"})
                    except Exception:
                        pass

                if "leak-lookup_priv" in active_keys and active_keys["leak-lookup_priv"]:
                    try:
                        current_target.get_leaklookup_priv(active_keys["leak-lookup_priv"], query_type)
                        audit_list.append({"engine": "Leak-Lookup (Private)", "status": "Searched"})
                    except Exception:
                        pass

                if "breachdirectory_user" in active_keys and active_keys.get("breachdirectory_pass"):
                    try:
                        current_target.get_breachdirectory(active_keys["breachdirectory_user"], active_keys["breachdirectory_pass"], query_type)
                        audit_list.append({"engine": "BreachDirectory", "status": "Searched"})
                    except Exception:
                        pass

            processed_targets.append(current_target)
            engine_audit_map[t_str] = audit_list

        # 3. High-Speed Local Breach File Search (Direct In-Memory Scan)
        resolved_cleartext_files = []
        if include_sample_db and os.path.exists(SAMPLE_BREACH_FILE):
            resolved_cleartext_files.append((SAMPLE_BREACH_FILE, "Sample Breach DB"))

        if local_breach_files:
            for raw_fp in local_breach_files:
                if not raw_fp:
                    continue
                resolved = self._resolve_path(raw_fp)
                if not resolved:
                    # Explicitly inform user that file was not found
                    for t in processed_targets:
                        engine_audit_map[t.target].append({
                            "engine": f"Local File ({os.path.basename(raw_fp) or raw_fp})",
                            "status": "File Not Found (Check Path)"
                        })
                    continue

                if os.path.isdir(resolved):
                    found_files = []
                    for root, _, filenames in os.walk(resolved):
                        for fn in sorted(filenames):
                            ext = os.path.splitext(fn)[1].lower()
                            if ext in (".txt", ".csv", ".lst", ".dump", ".tsv", ".log", ""):
                                full_p = os.path.join(root, fn)
                                if os.path.isfile(full_p):
                                    found_files.append(full_p)
                    if found_files:
                        for f_p in found_files:
                            entry = (f_p, f"{os.path.basename(resolved)}/{os.path.basename(f_p)}")
                            if entry not in resolved_cleartext_files:
                                resolved_cleartext_files.append(entry)
                    else:
                        for t in processed_targets:
                            engine_audit_map[t.target].append({
                                "engine": f"Local Dir ({os.path.basename(resolved)})",
                                "status": "No text files found in folder"
                            })
                elif os.path.isfile(resolved):
                    entry = (resolved, os.path.basename(resolved))
                    if entry not in resolved_cleartext_files:
                        resolved_cleartext_files.append(entry)

        if resolved_cleartext_files:
            for filepath, db_name in resolved_cleartext_files:
                try:
                    matched_targets = set()
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        for line_no, line in enumerate(f, start=1):
                            line_str = line.strip()
                            if not line_str or line_str.startswith("#"):
                                continue
                            line_lower = line_str.lower()
                            for t in processed_targets:
                                if t.target.lower() in line_lower:
                                    matched_targets.add(t.target)
                                    t.data.append((
                                        "LOCALSEARCH",
                                        f"[{os.path.basename(filepath)}] Line {line_no}: {line_str}"
                                    ))
                                    t.pwned += 1

                    for t in processed_targets:
                        status_str = "Match Found" if t.target in matched_targets else "Clean (0 matches)"
                        engine_audit_map[t.target].append({"engine": f"Local Dump ({db_name})", "status": status_str})
                except Exception as e:
                    for t in processed_targets:
                        engine_audit_map[t.target].append({"engine": f"Local Dump ({db_name})", "status": f"Error: {e}"})

        # 4. Local gzip files
        class DummyArgs:
            def __init__(self, debug_val):
                self.debug = debug_val

        dummy_args = DummyArgs(debug)

        if local_gzip_files:
            for raw_gz in local_gzip_files:
                if not raw_gz:
                    continue
                resolved_gz = self._resolve_path(raw_gz)
                if not resolved_gz:
                    for t in processed_targets:
                        engine_audit_map[t.target].append({
                            "engine": f"Gzip Archive ({os.path.basename(raw_gz) or raw_gz})",
                            "status": "File Not Found (Check Path)"
                        })
                    continue

                try:
                    files = find_files(resolved_gz, "gz")
                    if files:
                        local_found = local_gzip_search(files, targets)
                        if local_found:
                            processed_targets = local_to_targets(processed_targets, local_found, dummy_args)
                            for t in processed_targets:
                                engine_audit_map[t.target].append({
                                    "engine": f"Gzip Archive ({os.path.basename(resolved_gz)})",
                                    "status": "Match Found"
                                })
                        else:
                            for t in processed_targets:
                                engine_audit_map[t.target].append({
                                    "engine": f"Gzip Archive ({os.path.basename(resolved_gz)})",
                                    "status": "Clean (0 matches)"
                                })
                    else:
                        for t in processed_targets:
                            engine_audit_map[t.target].append({
                                "engine": f"Gzip Archive ({os.path.basename(resolved_gz)})",
                                "status": "No .gz files found"
                            })
                except Exception as e:
                    for t in processed_targets:
                        engine_audit_map[t.target].append({
                            "engine": f"Gzip Archive ({os.path.basename(resolved_gz)})",
                            "status": f"Error: {e}"
                        })

        # 5. Format results into structured dict
        results = []
        breached_count = 0

        for t in processed_targets:
            findings = []
            for item in t.data:
                if isinstance(item, tuple) and len(item) >= 2:
                    source = str(item[0])
                    detail = str(item[1])
                    if hide_passwords and len(detail) > 4:
                        detail = detail[:4] + "****"
                    findings.append({
                        "source": source,
                        "detail": detail
                    })

            is_pwned = (t.pwned > 0) or (len(findings) > 0)
            if is_pwned:
                breached_count += 1

            results.append({
                "target": t.target,
                "pwned_count": max(t.pwned, len(findings)),
                "is_breached": is_pwned,
                "status": f"Compromised ({max(t.pwned, len(findings))} breach findings)" if is_pwned else "Not Compromised",
                "findings": findings,
                "engines_checked": engine_audit_map.get(t.target, [])
            })

        execution_time = round(time.time() - start_time, 3)

        return {
            "success": True,
            "execution_time_seconds": execution_time,
            "total_targets": len(targets),
            "breached_targets": breached_count,
            "safe_targets": len(targets) - breached_count,
            "results": results
        }
