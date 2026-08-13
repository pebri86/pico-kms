from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    pkcs11_module: str
    pico_hsm_pin: str = ""
    pico_hsm_token_label: str | None = None
    pico_hsm_slot_id: int | None = None

    pico_kms_api_token: str = ""
    pico_kms_admin_token: str = ""

    kms_host: str = "127.0.0.1"
    kms_port: int = 8000


settings = Settings()
