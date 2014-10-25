package com.kryptnostic.api.v1.indexing;

import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
import com.kryptnostic.multivariate.util.SimplePolynomialFunctions;

public class Indexes {
    private Indexes() {}

    public static SimplePolynomialFunction generateRandomIndexingFunction(
            int nonceLength,
            int tokenLength,
            int locationLength ) {
        SimplePolynomialFunction outer = SimplePolynomialFunctions.denseRandomMultivariateQuadratic(
                locationLength,
                locationLength );
        SimplePolynomialFunction inner = SimplePolynomialFunctions.unsafeRandomManyToOneLinearCombination( nonceLength
                + tokenLength, locationLength );
        return outer.compose( inner );
    }

}
