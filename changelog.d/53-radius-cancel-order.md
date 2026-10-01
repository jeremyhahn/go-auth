### Fixed

- `pkg/radius`: a RADIUS/TLS exchange cancelled by its caller now always
  returns `context.Canceled` (or the deadline error) instead of sometimes
  `io.EOF` ([#53]). `context` closes a parent's `Done` channel before it
  cancels the children, so a peer that closed the connection in reaction to
  the caller's cancellation could fail the read while the exchange's derived
  context still read as live. The read error is now judged against the
  caller's context. A deterministic regression test reproduces the losing
  order with a parent context that withholds propagation.

[#53]: https://github.com/jeremyhahn/go-auth/issues/53
