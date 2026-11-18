package sampleservice

// KnownPoints lists every instrumentation point any workload can reach. It is
// the denominator for point coverage; points declared but never reached point
// at either dead code or an exploration budget too small to reach a branch.
func KnownPoints() []string {
	return []string{
		// coupons
		"coupon.redeem.check", "coupon.redeem.after_check",
		"coupon.redeem.write", "coupon.redeem.commit", "coupon.redeem.reject",
		// permissions
		"admin.check", "admin.after_check", "admin.commit", "admin.deny",
		"perm.revoke", "perm.revoke.done",
		// accounts
		"acct.debit.read", "acct.debit.after_read",
		"acct.debit.write", "acct.debit.commit", "acct.debit.reject",
	}
}
