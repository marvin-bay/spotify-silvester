"""Spotify auth and playback helpers."""
from __future__ import annotations

from dataclasses import dataclass

import spotipy
from spotipy.oauth2 import SpotifyOAuth

from config import AppConfig


SCOPES = "user-modify-playback-state user-read-playback-state"


def create_auth_manager(config: AppConfig) -> SpotifyOAuth:
    if not config.spotify_client_id:
        raise ValueError("Missing SPOTIFY_CLIENT_ID")
    if not config.spotify_client_secret:
        raise ValueError("Missing SPOTIFY_CLIENT_SECRET")
    if not config.spotify_redirect_uri:
        raise ValueError("Missing SPOTIFY_REDIRECT_URI")
    return SpotifyOAuth(
        client_id=config.spotify_client_id,
        client_secret=config.spotify_client_secret,
        redirect_uri=config.spotify_redirect_uri,
        scope=SCOPES,
        open_browser=True,
        cache_path=str(config.spotify_cache_path),
    )


def exchange_code_for_token(auth_manager: SpotifyOAuth, code: str) -> None:
    auth_manager.get_access_token(code=code, as_dict=False)


def create_spotify_client(auth_manager: SpotifyOAuth) -> spotipy.Spotify:
    client = spotipy.Spotify(auth_manager=auth_manager)
    # Trigger auth validation.
    client.current_user()
    return client


def ensure_active_device(client: spotipy.Spotify) -> None:
    devices = client.devices().get("devices", [])
    if not devices:
        raise RuntimeError(
            "No active Spotify device found. Open Spotify on a PC or phone."
        )


def start_playback(client: spotipy.Spotify, track_uri: str) -> None:
    client.start_playback(uris=[track_uri])


def queue_and_play_next(client: spotipy.Spotify, track_uri: str) -> None:
    client.add_to_queue(track_uri)
    client.next_track()
