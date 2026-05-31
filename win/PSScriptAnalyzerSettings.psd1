@{
    # PSScriptAnalyzer config for honey's Windows (PowerShell) variant.
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # honey writes plain no-BOM UTF-8 (comments contain — and → glyphs).
        # No-BOM UTF-8 is the modern cross-platform default and avoids breaking
        # tooling that doesn't expect a BOM; we deliberately do not add BOMs.
        'PSUseBOMForUnicodeEncodedFile',

        # Set-HoneyLatest writes a small pointer file (latest.txt). Adding
        # SupportsShouldProcess/-WhatIf plumbing to an internal helper that the
        # user never calls directly is noise, not safety.
        'PSUseShouldProcessForStateChangingFunctions'
    )
}
