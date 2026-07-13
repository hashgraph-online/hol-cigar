set shell := ["sh", "-eu", "-c"]

bootstrap:
    cargo xtask bootstrap

generate *args:
    cargo xtask generate {{args}}

fmt *args:
    cargo xtask fmt {{args}}

lint *args:
    cargo xtask lint {{args}}

test suite="all" *args:
    cargo xtask test {{suite}} {{args}}

docs *args:
    cargo xtask docs {{args}}

package profile="local":
    cargo xtask package --profile {{profile}}

