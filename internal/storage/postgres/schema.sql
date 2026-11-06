-- Схема применяется при старте сервиса. Скрипт идемпотентный (IF NOT EXISTS),
-- поэтому его безопасно выполнять при каждом запуске.
CREATE TABLE IF NOT EXISTS threats (
    md5         TEXT        PRIMARY KEY,
    name        TEXT        NOT NULL,
    sha256      TEXT        NOT NULL DEFAULT '',
    threat_type TEXT        NOT NULL DEFAULT '',
    severity    TEXT        NOT NULL DEFAULT '',
    file_size   BIGINT,
    description TEXT        NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL,

    -- Подстраховка на уровне БД: даже если в обход сервиса что-то запишут напрямую,
    -- мусорный хеш или отрицательный размер не пройдут.
    CONSTRAINT threats_md5_format CHECK (md5 ~ '^[a-f0-9]{32}$'),
    CONSTRAINT threats_file_size_nonneg CHECK (file_size IS NULL OR file_size >= 0)
);
