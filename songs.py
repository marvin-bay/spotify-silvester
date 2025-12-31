"""
Song schedule definitions.

Edit SONG_SCHEDULES to add or adjust tracks and target times.
Times are interpreted in local time and roll to the next day if needed.
Track title/artist/cover are fetched from Spotify by URI; label is shown as tooltip.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass(frozen=True)
class SongSchedule:
    label: str
    uri: str
    hour: int
    minute: int
    second: int

    def target_datetime(self, now: datetime | None = None) -> datetime:
        if now is None:
            now = datetime.now()
        target = now.replace(
            hour=self.hour,
            minute=self.minute,
            second=self.second,
            microsecond=0,
        )
        if target <= now:
            target = target + timedelta(days=1)
        return target

def display_time(self) -> str:
        return f"{self.hour:02d}:{self.minute:02d}:{self.second:02d}"


TEST_LABEL = "TEST! Roy Bianco & Die Abbrunzati Boys - Goodbye, Arrividerci"

SONG_SCHEDULES = [
    SongSchedule(
        label="Slipknot - People = Shit",
        uri="spotify:track:0Y2i84QWPFiFHQfEQDgHya",
        hour=23,
        minute=59,
        second=30,
    ),
    SongSchedule(
        label="Roy Bianco & Die Abbrunzati Boys - Goodbye, Arrividerci",
        uri="spotify:track:3bkYCvyfgJPR3pHMHiuHv7",
        hour=23,
        minute=56,
        second=41,
    ),
    SongSchedule(
        label=TEST_LABEL,
        uri="spotify:track:3bkYCvyfgJPR3pHMHiuHv7",
        hour=1,
        minute=20,
        second=50,
    ),
    SongSchedule(
        label="Kapelle Petra - Heute ist Geburtstag",
        uri="spotify:track:3Ij5CdpZYQ9KJ4YyQ0WVVJ",
        hour=23,
        minute=59,
        second=49,
    ),
    SongSchedule(
        label="Lynyrd Skynyrd - Free Bird",
        uri="spotify:track:5EWPGh7jbTNO2wakv8LjUI",
        hour=23,
        minute=55,
        second=5,
    ),
]
