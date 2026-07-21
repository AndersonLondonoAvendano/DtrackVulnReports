"""Tipos de query param opcionales tolerantes a cadena vacía.

Los filtros opcionales de un formulario HTML (`<input>`/`<select>` sin valor)
se envían como `campo=` (cadena vacía), no simplemente omitidos. FastAPI/
Pydantic rechazan eso con 422 para un query param tipado `float | None` o
`int | None` -- "" no es ni un número válido ni `None`. Estos alias se
normalizan antes de la validación de tipo para que "" se trate como ausente.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import Query
from pydantic import BeforeValidator


def _empty_str_to_none(value: object) -> object:
    return None if value == "" else value


# Nota: el default (`= None`) se asigna en el sitio de uso, no aquí -- FastAPI
# no permite combinar `Query(default=...)` dentro de `Annotated` con un
# default también puesto ahí; el propio `Query()` (sin default) debe ir en el
# `Annotated` y el default real de Python fuera de él.
OptionalFloatQuery = Annotated[float | None, BeforeValidator(_empty_str_to_none), Query()]
OptionalIntQuery = Annotated[int | None, BeforeValidator(_empty_str_to_none), Query()]
OptionalStrQuery = Annotated[str | None, BeforeValidator(_empty_str_to_none), Query()]
