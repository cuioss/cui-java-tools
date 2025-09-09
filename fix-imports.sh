#!/bin/bash

# Fix import statements for moved generators

# Cookie generators
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.ValidCookieGenerator;/import de.cuioss.tools.security.http.generators.cookie.ValidCookieGenerator;/g' {} \;
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.AttackCookieGenerator;/import de.cuioss.tools.security.http.generators.cookie.AttackCookieGenerator;/g' {} \;
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.CookieGenerator;/import de.cuioss.tools.security.http.generators.cookie.CookieGenerator;/g' {} \;
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.CookieInjectionAttackGenerator;/import de.cuioss.tools.security.http.generators.cookie.CookieInjectionAttackGenerator;/g' {} \;

# URL generators
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.ValidURLGenerator;/import de.cuioss.tools.security.http.generators.url.ValidURLGenerator;/g' {} \;
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.InvalidURLGenerator;/import de.cuioss.tools.security.http.generators.url.InvalidURLGenerator;/g' {} \;
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.ValidURLParameterGenerator;/import de.cuioss.tools.security.http.generators.url.ValidURLParameterGenerator;/g' {} \;
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.AttackURLParameterGenerator;/import de.cuioss.tools.security.http.generators.url.AttackURLParameterGenerator;/g' {} \;
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.URLParameterGenerator;/import de.cuioss.tools.security.http.generators.url.URLParameterGenerator;/g' {} \;
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.ValidURLParameterStringGenerator;/import de.cuioss.tools.security.http.generators.url.ValidURLParameterStringGenerator;/g' {} \;
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.ValidURLPathGenerator;/import de.cuioss.tools.security.http.generators.url.ValidURLPathGenerator;/g' {} \;
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.PathTraversalParameterGenerator;/import de.cuioss.tools.security.http.generators.url.PathTraversalParameterGenerator;/g' {} \;
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.NullByteInjectionParameterGenerator;/import de.cuioss.tools.security.http.generators.url.NullByteInjectionParameterGenerator;/g' {} \;
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.NullByteURLGenerator;/import de.cuioss.tools.security.http.generators.url.NullByteURLGenerator;/g' {} \;
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.PathTraversalURLGenerator;/import de.cuioss.tools.security.http.generators.url.PathTraversalURLGenerator;/g' {} \;
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.URLLengthLimitAttackGenerator;/import de.cuioss.tools.security.http.generators.url.URLLengthLimitAttackGenerator;/g' {} \;

# Header generators
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.ValidHTTPHeaderNameGenerator;/import de.cuioss.tools.security.http.generators.header.ValidHTTPHeaderNameGenerator;/g' {} \;
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.InvalidHTTPHeaderNameGenerator;/import de.cuioss.tools.security.http.generators.header.InvalidHTTPHeaderNameGenerator;/g' {} \;
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.ValidHTTPHeaderValueGenerator;/import de.cuioss.tools.security.http.generators.header.ValidHTTPHeaderValueGenerator;/g' {} \;
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.HTTPHeaderInjectionGenerator;/import de.cuioss.tools.security.http.generators.header.HTTPHeaderInjectionGenerator;/g' {} \;

# Body generators
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.HTTPBodyGenerator;/import de.cuioss.tools.security.http.generators.body.HTTPBodyGenerator;/g' {} \;
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.ValidHTTPBodyContentGenerator;/import de.cuioss.tools.security.http.generators.body.ValidHTTPBodyContentGenerator;/g' {} \;

# Encoding generators
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.EncodingCombinationGenerator;/import de.cuioss.tools.security.http.generators.encoding.EncodingCombinationGenerator;/g' {} \;
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.PathTraversalGenerator;/import de.cuioss.tools.security.http.generators.encoding.PathTraversalGenerator;/g' {} \;
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.UnicodeAttackGenerator;/import de.cuioss.tools.security.http.generators.encoding.UnicodeAttackGenerator;/g' {} \;
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.BoundaryFuzzingGenerator;/import de.cuioss.tools.security.http.generators.encoding.BoundaryFuzzingGenerator;/g' {} \;
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.ComplexEncodingCombinationGenerator;/import de.cuioss.tools.security.http.generators.encoding.ComplexEncodingCombinationGenerator;/g' {} \;
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.DoubleEncodingAttackGenerator;/import de.cuioss.tools.security.http.generators.encoding.DoubleEncodingAttackGenerator;/g' {} \;
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.MixedEncodingAttackGenerator;/import de.cuioss.tools.security.http.generators.encoding.MixedEncodingAttackGenerator;/g' {} \;
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.UnicodeControlCharacterAttackGenerator;/import de.cuioss.tools.security.http.generators.encoding.UnicodeControlCharacterAttackGenerator;/g' {} \;
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.UnicodeNormalizationAttackGenerator;/import de.cuioss.tools.security.http.generators.encoding.UnicodeNormalizationAttackGenerator;/g' {} \;

# Injection generators
find src/test/java -name "*.java" -exec sed -i '' 's/import de\.cuioss\.tools\.security\.http\.generators\.\(.*Attack.*\);/import de.cuioss.tools.security.http.generators.injection.\1;/g' {} \;

echo "Import statements updated successfully!"