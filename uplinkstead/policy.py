"""Pure policy used by the real agent. No wall-clock deadlines or hidden fallback."""
from dataclasses import dataclass, field
import math


@dataclass(frozen=True)
class Settings:
    failures: int = 3
    successes: int = 3
    freshness: float = 2.0
    stable: float = 30.0
    window: float = 60.0
    budget: int = 3
    auto_failback: bool = False

    def __post_init__(self):
        if type(self.auto_failback) is not bool:
            raise ValueError('Invalid auto_failback')
        for name in ('failures', 'successes', 'budget'):
            if type(getattr(self, name)) is not int or getattr(self, name) < 1:
                raise ValueError('Invalid count')
        for name in ('freshness', 'stable', 'window'):
            if type(getattr(self, name)) not in (int, float) or not math.isfinite(getattr(self, name)) or getattr(self, name) <= 0:
                raise ValueError('Invalid duration')


@dataclass
class Health:
    state: str = 'UNKNOWN'
    good: int = 0
    bad: int = 0
    since: float | None = None
    last: float | None = None
    round: int = -1


class Policy:
    def __init__(self, settings, config_hash, boot, history=(), latched=False):
        self.s = settings
        self.hash = config_hash
        self.boot = boot
        self.links = {k: Health() for k in ('A', 'B')}
        self.history = list(history)
        self.latched = latched

    def observe(self, link, round_id, started, finished, now, successes, config_hash, boot):
        h = self.links[link]
        if config_hash != self.hash or boot != self.boot or round_id <= h.round:
            return False
        if not all(math.isfinite(x) for x in (started, finished, now)) or not (0 <= started <= finished <= now):
            return False
        h.round = round_id
        # Expired / infrastructure failures break consecutive streaks.
        if now - started > self.s.freshness or successes is None:
            h.state, h.good, h.bad, h.since, h.last = 'UNKNOWN', 0, 0, None, None
            return False
        if h.last is not None and started - h.last > self.s.freshness:
            h.good, h.bad, h.since = 0, 0, None
        h.last = finished
        if successes >= 2:
            h.bad = 0
            h.good += 1
            if h.since is None:
                h.since = started
            if h.good >= self.s.successes:
                h.state = 'HEALTHY'
            else:
                h.state = 'RECOVERING'
        else:
            h.good, h.since = 0, None
            h.bad += 1
            h.state = 'DOWN' if h.bad >= self.s.failures else 'SUSPECT'
        return True

    def fresh(self, link, now):
        h = self.links[link]
        if h.last is None or now - h.last > self.s.freshness:
            h.state, h.good, h.bad, h.since, h.last = 'UNKNOWN', 0, 0, None, None
        return h.state

    def candidate(self, selected, now):
        a, b = self.fresh('A', now), self.fresh('B', now)
        if self.latched:
            return None, 'DEGRADED_LATCHED'
        if selected is None:
            target = 'A' if a == 'HEALTHY' else ('B' if b == 'HEALTHY' else None)
        elif self.links[selected].state == 'DOWN':
            other = 'B' if selected == 'A' else 'A'
            target = other if self.links[other].state == 'HEALTHY' else None
        elif selected == 'B' and self.s.auto_failback and a == 'HEALTHY' and now - self.links['A'].since >= self.s.stable:
            target = 'A'
        else:
            target = None
        if target is None:
            return None, ('NO_HEALTHY_UPLINK' if a != 'HEALTHY' and b != 'HEALTHY' else 'RUNNING')
        # Cross-boot event ages are unknown; count them until an entire new window
        # has elapsed in this boot. Process restart does not reset CLOCK_BOOTTIME.
        recent = [e for e in self.history if
                  (e['boot'] == self.boot and now - e['at'] <= self.s.window) or
                  (e['boot'] != self.boot and now <= self.s.window)]
        if len(recent) >= self.s.budget:
            self.latched = True
            return None, 'DEGRADED_LATCHED'
        return target, 'SWITCHING'

    def admit(self, now):
        e = {'boot': self.boot, 'at': now}
        self.history.append(e)
        return e

    def proof(self, link, instant):
        if self.fresh(link,instant) != 'HEALTHY':
            raise ValueError('Destination lacks fresh health')
        h=self.links[link]
        return dict(config_hash=self.hash,boot=self.boot,target=link,round=h.round,
                    observed_at=h.last,expires_at=h.last+self.s.freshness)
