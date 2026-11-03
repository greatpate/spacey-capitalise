/**
 * Guards against known-vulnerable dependency versions creeping back in.
 * Runs in plain Node (no VS Code required): `npm run test:unit`.
 *
 * Each entry lists the vulnerable semver range reported by `npm audit`
 * (GitHub advisories) and the dependabot PR / advisory it relates to.
 */
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const semver = require('semver');

const VULNERABLE = {
	lodash: '<=4.17.23', // dependabot #4 (command injection / prototype pollution)
	'glob-parent': '<5.1.2', // dependabot #5 (ReDoS)
	ajv: '<6.12.7', // dependabot #6 (CVE-2020-15366)
	flat: '<5.0.1', // dependabot #7 (prototype pollution)
	mocha: '<10.2.0', // dependabot #7
	minimist: '<=0.2.3',
	mkdirp: '0.4.1 - 0.5.1',
	'yargs-parser': '6.0.0 - 13.1.1',
	'js-yaml': '<=3.15.1',
	minimatch: '<11.0.1',
	'brace-expansion': '<=1.1.20',
	semver: '2.0.0-alpha - 5.7.1 || 6.0.0 - 6.3.0',
	'cross-spawn': '<6.0.6',
	'ansi-regex': '3.0.0 || 4.0.0 - 4.1.0 || 5.0.0',
	'word-wrap': '<1.2.4',
	tmp: '<=0.2.5',
	glob: '<14.0.2', // via minimatch ReDoS / AbortSignal advisory
	flatted: '<=3.4.1',
	diff: '<3.5.1',
	debug: '3.2.0 - 3.2.6 || 4.0.0 - 4.3.0',
	eslint: '4.0.0-alpha.0 - 7.14.0'
};

/** Collect every installed {name, version} from either lockfile format. */
function lockedPackages(lock) {
	const found = [];
	if (lock.packages) {
		for (const [p, info] of Object.entries(lock.packages)) {
			const name = info.name || p.split('node_modules/').pop();
			if (name && info.version) found.push({ name, version: info.version });
		}
	} else {
		(function walk(deps) {
			for (const [name, info] of Object.entries(deps || {})) {
				found.push({ name, version: info.version });
				walk(info.dependencies);
			}
		})(lock.dependencies);
	}
	return found;
}

suite('Dependency security', () => {
	const lock = JSON.parse(
		fs.readFileSync(path.resolve(__dirname, '../../package-lock.json'), 'utf8')
	);
	const packages = lockedPackages(lock);

	test('lockfile lists packages', () => {
		assert.ok(packages.length > 0);
	});

	Object.entries(VULNERABLE).forEach(([name, range]) => {
		test(`${name} has no installed version in vulnerable range ${range}`, () => {
			const bad = packages
				.filter(p => p.name === name && semver.valid(p.version))
				.filter(p => semver.satisfies(p.version, range, { includePrerelease: true }))
				.map(p => p.version);
			assert.deepStrictEqual(bad, [], `vulnerable ${name}: ${bad.join(', ')}`);
		});
	});
});
