package conformance

// normalizeOriginProduct retains only coarse, self-reported statistics metadata.
func normalizeOriginProduct(product string) string {
	switch product {
	case "desktop", "cli", "qurl_link", "other", "unknown":
		return product
	default:
		return "unknown"
	}
}
