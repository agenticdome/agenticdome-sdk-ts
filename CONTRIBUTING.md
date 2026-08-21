# Contributing to the AgenticDome TypeScript SDK

## Local verification

```bash
npm ci
npm run typecheck
npm test
npm run build
npm pack --dry-run
```

## SDK and integration changes

- Keep changes focused on public client behavior and stable public interfaces.
- Add or update tests for every behavior change.
- When adding an integration example, use placeholder credentials and synthetic data, demonstrate both allowed and blocked decisions, and document the application boundary that must not bypass the SDK.
- Do not publish private endpoints, tenant evidence, detection rules, internal policy logic, or server-side implementation.

## Pull requests

Explain the user-visible behavior, security impact, tests performed, and documentation changes. Security-sensitive changes require maintainer review and may require design changes before merge. By submitting a contribution, you agree that it is provided under the repository's Apache-2.0 license.

For ordinary questions and reproducible defects, use the public [issue tracker](https://github.com/agenticdome/agenticdome-sdk-ts/issues). Report vulnerabilities privately to **info@agenticdome.io** under [SECURITY.md](SECURITY.md).
