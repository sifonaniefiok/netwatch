"""Allow ``python -m netwatch`` as an alternative to the ``netwatch`` console script."""

from netwatch.cli import main

raise SystemExit(main())
