"""A read-only PostgreSQL business-effect observer.

The operator provisions the connection and a bounded template: a schema, a table and
the columns that carry correlation, tenant, resource, state and time. There is no
arbitrary SQL anywhere: identifiers are validated, composed with psycopg.sql and run
in a read-only transaction with a statement timeout and a row limit. The connection
string is never stored in a record; it is read from an operator-provisioned
environment variable named by a slug.

The observer answers only in the observer vocabulary, and every ambiguity is UNKNOWN:
duplicate matches, an unmapped state, a candidate outside the observation window, a
match belonging to another tenant, or an unreachable system of record.
"""

import os
import re
from typing import Literal

import psycopg
from psycopg import sql
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .observer_platform import FACTS

IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
SLUG = re.compile(r"^[A-Z][A-Z0-9_]{0,39}$")
ENV_PREFIX = "TV_OBSERVER_DSN_"


class ObserverUnavailable(RuntimeError):
    """The system of record could not be read. It never means "no effect"."""


class SqlObserverConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    connection: str = Field(description="Operator slug; the DSN comes from TV_OBSERVER_DSN_<slug>")
    schema_name: str
    table: str
    correlation_column: str
    state_column: str
    occurred_at_column: str
    resource_column: str | None = None
    tenant_column: str | None = None
    tenant_value: str | None = Field(default=None, max_length=200)
    state_map: dict[str, Literal[FACTS]] = Field(min_length=1, max_length=20)  # type: ignore[valid-type]
    row_limit: int = Field(default=10, ge=1, le=100)
    statement_timeout_ms: int = Field(default=2000, ge=100, le=10000)

    @field_validator("connection")
    @classmethod
    def slug(cls, value):
        if not SLUG.fullmatch(value):
            raise ValueError("The connection slug must be upper-case letters, digits and underscores")
        return value

    @field_validator("schema_name", "table", "correlation_column", "state_column", "occurred_at_column",
                     "resource_column", "tenant_column")
    @classmethod
    def identifier(cls, value):
        if value is not None and not IDENTIFIER.fullmatch(value):
            raise ValueError("Only plain lower-case SQL identifiers are accepted")
        return value

    @field_validator("state_map")
    @classmethod
    def bounded_states(cls, value):
        for key in value:
            if not isinstance(key, str) or not 1 <= len(key) <= 100:
                raise ValueError("Each source state must be short text")
        return value

    @model_validator(mode="after")
    def tenant_pair(self):
        if (self.tenant_column is None) != (self.tenant_value is None):
            raise ValueError("A tenant column and its expected value are configured together")
        return self


def dsn(config):
    name = ENV_PREFIX + config.connection
    value = os.environ.get(name)
    if not value:
        raise ObserverUnavailable(f"{name} is not provisioned for this deployment")
    return value.replace("postgresql+psycopg://", "postgresql://")


def _connect(config, connect):
    return (connect or (lambda: psycopg.connect(dsn(config))))()


def _query(config, *, scoped):
    columns = [config.correlation_column, config.state_column, config.occurred_at_column]
    columns += [c for c in (config.resource_column, config.tenant_column) if c]
    where = [sql.SQL("{} = %(correlation)s").format(sql.Identifier(config.correlation_column))]
    if scoped:
        where.append(sql.SQL("{} >= %(start)s").format(sql.Identifier(config.occurred_at_column)))
        where.append(sql.SQL("{} <= %(end)s").format(sql.Identifier(config.occurred_at_column)))
        if config.tenant_column:
            where.append(sql.SQL("{} = %(tenant)s").format(sql.Identifier(config.tenant_column)))
    statement = sql.SQL("SELECT {columns} FROM {table} WHERE {where} ORDER BY {order} LIMIT {limit}").format(
        columns=sql.SQL(", ").join(sql.Identifier(c) for c in columns),
        table=sql.Identifier(config.schema_name, config.table),
        where=sql.SQL(" AND ").join(where), order=sql.Identifier(config.occurred_at_column),
        limit=sql.Literal(config.row_limit + 1 if scoped else 2))
    return statement, columns


def read_rows(config, *, correlation_value, window_start, window_end, scoped=True, connect=None):
    """Bounded read-only read. Raises ObserverUnavailable; never writes, never retries."""
    statement, columns = _query(config, scoped=scoped)
    parameters = {"correlation": correlation_value, "start": window_start, "end": window_end,
                  "tenant": config.tenant_value}
    try:
        connection = _connect(config, connect)
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION READ ONLY")
                cursor.execute(sql.SQL("SET LOCAL statement_timeout = {}").format(
                    sql.Literal(config.statement_timeout_ms)))
                cursor.execute(statement, parameters)
                rows = [dict(zip(columns, row, strict=True)) for row in cursor.fetchall()]
            connection.rollback()
        finally:
            connection.close()
    except psycopg.Error as error:
        raise ObserverUnavailable(type(error).__name__) from None
    return rows


def _answer(effect, reason, **extra):
    return {"effect": effect, "reason": reason, **extra}


def observe(config, *, correlation_value, window_start, window_end, covers_commit=True,
            absence_is_denial=False, covered=True, connect=None):
    """One answer from the observer vocabulary for one attempted effect."""
    if not covered:
        return _answer("UNKNOWN", "The requested effect is outside what this observer can see.")
    if not correlation_value:
        return _answer("UNKNOWN", "No correlation value reached the system of record.")
    try:
        rows = read_rows(config, correlation_value=correlation_value, window_start=window_start,
                         window_end=window_end, connect=connect)
    except ObserverUnavailable as error:
        return _answer("UNKNOWN", f"The system of record is unreachable ({error}).")
    if len(rows) > config.row_limit:
        return _answer("UNKNOWN", "More matching records than this observer may interpret.")
    if not rows:
        try:
            elsewhere = read_rows(config, correlation_value=correlation_value, window_start=window_start,
                                  window_end=window_end, scoped=False, connect=connect)
        except ObserverUnavailable as error:
            return _answer("UNKNOWN", f"The system of record is unreachable ({error}).")
        if elsewhere:
            candidate = elsewhere[0]
            if config.tenant_column and str(candidate.get(config.tenant_column)) != str(config.tenant_value):
                return _answer("UNKNOWN", "A record with this correlation value belongs to another tenant.")
            return _answer("UNKNOWN", "The only candidate record falls outside the observation window.")
        if covers_commit and absence_is_denial:
            return _answer("DENIED", "This observer covers commits for this resource and found none; no effect "
                                     "committed inside its observation window.")
        return _answer("UNKNOWN", "No record was found, and this observer cannot establish absence of an effect.")
    effects = []
    for row in rows:
        mapped = config.state_map.get(str(row[config.state_column]))
        if mapped is None:
            return _answer("UNKNOWN", "A matching record carries a state this observer has no reviewed mapping for.")
        effects.append(mapped)
    if len(effects) != len(set(effects)):
        return _answer("UNKNOWN", "Several indistinguishable records match this correlation value.")
    if "COMPENSATED" in effects:
        return _answer("COMPENSATED", "A committed effect was reversed. The commit still happened.",
                       committed="COMMITTED" in effects)
    if "COMMITTED" in effects:
        return _answer("COMMITTED", "The system of record durably holds this effect.")
    if "DENIED" in effects:
        return _answer("DENIED", "A control refused the attempt before any effect could commit.")
    return _answer("UNKNOWN", "Only pre-commit facts were found; the outcome is not established.")
