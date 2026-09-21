<?php

declare(strict_types=1);

final class NmapService
{
    private const PROFILES = [
        'quick' => ['-T4', '-F', '-n'],
        'service' => ['-sV', '--version-light', '-T4', '-n', '--top-ports', '100'],
    ];

    public function validateTarget(string $target, string $allowlist): array
    {
        if (!preg_match('/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d|[12]\d|3[0-2]))?$/', $target, $matches)) {
            return [false, 'Use a single IPv4 address or CIDR. Hostnames and extra Nmap options are not accepted.'];
        }
        $ip = $matches[1];
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false || !$this->isPrivateIp($ip)) {
            return [false, 'Only RFC1918 private lab IPv4 targets are allowed.'];
        }

        $prefix = isset($matches[2]) && $matches[2] !== '' ? (int) $matches[2] : 32;
        $allowed = array_filter(array_map('trim', preg_split('/[\r\n,]+/', $allowlist) ?: []));
        foreach ($allowed as $cidr) {
            if ($this->subnetWithinCidr($ip, $prefix, $cidr)) {
                return [true, 'Target approved.'];
            }
        }

        return [false, 'Target is private but is not inside the configured lab allowlist.'];
    }

    public function run(string $target, string $profile): array
    {
        if (!config('nmap.enabled')) {
            return ['Blocked', 'Nmap scans are disabled. Set ENABLE_NMAP_SCANS=true in .env after obtaining written authorisation for the lab.'];
        }
        if (!isset(self::PROFILES[$profile])) {
            return ['Blocked', 'Unknown scan profile.'];
        }

        $command = array_merge([(string) config('nmap.binary')], self::PROFILES[$profile], ['--', $target]);
        $descriptors = [
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $process = @proc_open($command, $descriptors, $pipes, WATCHU_ROOT, null, ['bypass_shell' => true]);
        if (!is_resource($process)) {
            return ['Failed', 'Unable to start Nmap. Confirm that Nmap is installed and NMAP_BINARY is correct.'];
        }

        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $output = '';
        $started = time();
        do {
            $output .= stream_get_contents($pipes[1]) ?: '';
            $output .= stream_get_contents($pipes[2]) ?: '';
            $status = proc_get_status($process);
            if (!$status['running']) {
                break;
            }
            if (time() - $started > 60) {
                proc_terminate($process);
                $output .= "\nScan stopped after the 60-second safety limit.";
                break;
            }
            usleep(100000);
        } while (true);

        $output .= stream_get_contents($pipes[1]) ?: '';
        $output .= stream_get_contents($pipes[2]) ?: '';
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($process);

        return [$exitCode === 0 ? 'Completed' : 'Failed', trim($output) ?: 'Nmap returned no output.'];
    }

    private function isPrivateIp(string $ip): bool
    {
        $value = sprintf('%u', ip2long($ip));
        $number = (int) $value;
        return ($number >= 167772160 && $number <= 184549375)
            || ($number >= 2886729728 && $number <= 2887778303)
            || ($number >= 3232235520 && $number <= 3232301055);
    }

    private function subnetWithinCidr(string $ip, int $prefix, string $allowedCidr): bool
    {
        if (!preg_match('/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d|[12]\d|3[0-2])$/', $allowedCidr, $match)
            || filter_var($match[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return false;
        }

        $allowedPrefix = (int) $match[2];
        if ($prefix < $allowedPrefix) {
            return false;
        }
        $mask = $allowedPrefix === 0 ? 0 : ((0xFFFFFFFF << (32 - $allowedPrefix)) & 0xFFFFFFFF);
        return ((ip2long($ip) & $mask) === (ip2long($match[1]) & $mask));
    }
}

