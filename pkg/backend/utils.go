package backend

import "strings"

func rewriteSetCookieDomain(sc, host string, secure bool) string {
	parts := strings.Split(sc, ";")
	out := make([]string, 0, len(parts)+2)
	domainSet := false
	for _, p := range parts {
		k := strings.TrimSpace(p)
		if strings.HasPrefix(strings.ToLower(k), "domain=") {
			// overwrite with current host
			out = append(out, "Domain="+host)
			domainSet = true
			continue
		}
		out = append(out, k)
	}
	if !domainSet {
		// Leave host-only cookie (no Domain attr) -> browser uses current host
	}
	// Ensure Secure flag if desired
	if secure && !containsAttr(out, "Secure") {
		out = append(out, "Secure")
	}
	// Ensure SameSite=Lax if not present
	if !hasSameSiteAttr(out) {
		out = append(out, "SameSite=Lax")
	}
	return strings.Join(out, "; ")
}

func containsAttr(attrs []string, attr string) bool {
	attrLower := strings.ToLower(attr)
	for _, a := range attrs {
		if strings.ToLower(strings.TrimSpace(a)) == attrLower {
			return true
		}
	}
	return false
}

func hasSameSiteAttr(attrs []string) bool {
	for _, a := range attrs {
		a = strings.TrimSpace(a)
		if strings.HasPrefix(strings.ToLower(a), "samesite=") {
			return true
		}
	}
	return false
}
