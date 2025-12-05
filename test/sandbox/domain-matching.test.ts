import { describe, test, expect } from 'bun:test'
import { matchesDomainPattern } from '../../src/sandbox/sandbox-utils.js'

describe('matchesDomainPattern', () => {
  describe('exact match patterns', () => {
    test('matches exact domain', () => {
      expect(matchesDomainPattern('example.com', 'example.com')).toBe(true)
    })

    test('does not match different domain', () => {
      expect(matchesDomainPattern('other.com', 'example.com')).toBe(false)
    })

    test('does not match subdomain for exact pattern', () => {
      expect(matchesDomainPattern('api.example.com', 'example.com')).toBe(false)
    })

    test('case insensitive matching', () => {
      expect(matchesDomainPattern('Example.COM', 'example.com')).toBe(true)
      expect(matchesDomainPattern('example.com', 'EXAMPLE.COM')).toBe(true)
    })
  })

  describe('subdomain wildcard patterns (*.example.com)', () => {
    test('matches direct subdomain', () => {
      expect(matchesDomainPattern('api.example.com', '*.example.com')).toBe(
        true,
      )
    })

    test('matches nested subdomain', () => {
      expect(
        matchesDomainPattern('deep.api.example.com', '*.example.com'),
      ).toBe(true)
    })

    test('does NOT match base domain', () => {
      expect(matchesDomainPattern('example.com', '*.example.com')).toBe(false)
    })

    test('does not match different domain suffix', () => {
      expect(
        matchesDomainPattern('malicious-example.com', '*.example.com'),
      ).toBe(false)
    })

    test('case insensitive', () => {
      expect(matchesDomainPattern('API.Example.COM', '*.example.com')).toBe(
        true,
      )
    })
  })

  describe('dot-prefix patterns (.example.com) - NEW', () => {
    test('matches base domain', () => {
      expect(matchesDomainPattern('example.com', '.example.com')).toBe(true)
    })

    test('matches direct subdomain', () => {
      expect(matchesDomainPattern('api.example.com', '.example.com')).toBe(true)
    })

    test('matches nested subdomain', () => {
      expect(matchesDomainPattern('deep.api.example.com', '.example.com')).toBe(
        true,
      )
    })

    test('does not match different domain suffix', () => {
      expect(
        matchesDomainPattern('malicious-example.com', '.example.com'),
      ).toBe(false)
    })

    test('case insensitive', () => {
      expect(matchesDomainPattern('API.Example.COM', '.example.com')).toBe(true)
      expect(matchesDomainPattern('EXAMPLE.COM', '.example.com')).toBe(true)
    })

    test('works with co.uk style domains', () => {
      expect(matchesDomainPattern('example.co.uk', '.example.co.uk')).toBe(true)
      expect(matchesDomainPattern('www.example.co.uk', '.example.co.uk')).toBe(
        true,
      )
    })
  })

  describe('match-all wildcard (*) - NEW', () => {
    test('matches any domain', () => {
      expect(matchesDomainPattern('example.com', '*')).toBe(true)
      expect(matchesDomainPattern('api.github.com', '*')).toBe(true)
      expect(matchesDomainPattern('localhost', '*')).toBe(true)
    })

    test('matches IP addresses', () => {
      expect(matchesDomainPattern('192.168.1.1', '*')).toBe(true)
      expect(matchesDomainPattern('1.1.1.1', '*')).toBe(true)
    })

    test('matches empty hostname', () => {
      expect(matchesDomainPattern('', '*')).toBe(true)
    })
  })

  describe('localhost', () => {
    test('exact match for localhost', () => {
      expect(matchesDomainPattern('localhost', 'localhost')).toBe(true)
    })

    test('wildcard matches localhost', () => {
      expect(matchesDomainPattern('localhost', '*')).toBe(true)
    })
  })

  describe('edge cases', () => {
    test('empty hostname with non-wildcard pattern', () => {
      expect(matchesDomainPattern('', 'example.com')).toBe(false)
    })

    test('pattern priority demonstration', () => {
      // This shows the semantic difference between patterns
      const hostname = 'example.com'
      expect(matchesDomainPattern(hostname, 'example.com')).toBe(true) // exact
      expect(matchesDomainPattern(hostname, '*.example.com')).toBe(false) // subdomain only
      expect(matchesDomainPattern(hostname, '.example.com')).toBe(true) // base + subdomains
    })

    test('subdomain with dot-prefix pattern', () => {
      const subdomain = 'api.example.com'
      expect(matchesDomainPattern(subdomain, 'example.com')).toBe(false) // exact doesn't match
      expect(matchesDomainPattern(subdomain, '*.example.com')).toBe(true) // subdomain matches
      expect(matchesDomainPattern(subdomain, '.example.com')).toBe(true) // dot-prefix matches
    })
  })
})
