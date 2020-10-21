/*
 * Copyright 2016-2020 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.openicf.connectors.google;

import static org.identityconnectors.framework.common.objects.filter.FilterBuilder.and;
import static org.identityconnectors.framework.common.objects.filter.FilterBuilder.not;
import static org.identityconnectors.framework.common.objects.filter.FilterBuilder.or;

import org.identityconnectors.framework.common.objects.filter.AbstractFilterTranslator;
import org.identityconnectors.framework.common.objects.filter.ContainsAllValuesFilter;
import org.identityconnectors.framework.common.objects.filter.ContainsFilter;
import org.identityconnectors.framework.common.objects.filter.EndsWithFilter;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.Filter;
import org.identityconnectors.framework.common.objects.filter.GreaterThanFilter;
import org.identityconnectors.framework.common.objects.filter.GreaterThanOrEqualFilter;
import org.identityconnectors.framework.common.objects.filter.LessThanFilter;
import org.identityconnectors.framework.common.objects.filter.LessThanOrEqualFilter;
import org.identityconnectors.framework.common.objects.filter.StartsWithFilter;

/**
 * This is an implementation of AbstractFilterTranslator that gives a concrete representation
 * of which filters can be applied at the connector level (natively).
 * <p>
 * If the GoogleIotHub doesn't support a certain expression type, that factory
 * method should return null. This level of filtering is present only to allow any
 * native constructs that may be available to help reduce the result set for the framework,
 * which will (strictly) reapply all filters specified after the connector does the initial
 * filtering.<p><p>Note: The generic query type is most commonly a String, but does not have to be.
 */
public class GCPIoTCoreFilterTranslator extends AbstractFilterTranslator<Filter> {

    @Override
    protected Filter createAndExpression(final Filter leftExpression, final Filter rightExpression) {
        return and(leftExpression, rightExpression);
    }

    @Override
    protected Filter createContainsAllValuesExpression(final ContainsAllValuesFilter filter, boolean not) {
        return not ? not(filter) : filter;
    }

    @Override
    protected Filter createContainsExpression(final ContainsFilter filter, boolean not) {
        return not ? not(filter) : filter;
    }

    @Override
    protected Filter createEndsWithExpression(final EndsWithFilter filter, boolean not) {
        return not ? not(filter) : filter;
    }

    @Override
    protected Filter createEqualsExpression(final EqualsFilter filter, boolean not) {
        return not ? not(filter) : filter;
    }

    @Override
    protected Filter createGreaterThanExpression(final GreaterThanFilter filter, boolean not) {
        return not ? not(filter) : filter;
    }

    @Override
    protected Filter createGreaterThanOrEqualExpression(final GreaterThanOrEqualFilter filter, boolean not) {
        return not ? not(filter) : filter;
    }

    @Override
    protected Filter createLessThanExpression(final LessThanFilter filter, boolean not) {
        return not ? not(filter) : filter;
    }

    @Override
    protected Filter createLessThanOrEqualExpression(final LessThanOrEqualFilter filter, boolean not) {
        return not ? not(filter) : filter;
    }

    @Override
    protected Filter createOrExpression(final Filter leftExpression, final Filter rightExpression) {
        return or(leftExpression, rightExpression);
    }

    @Override
    protected Filter createStartsWithExpression(final StartsWithFilter filter, boolean not) {
        return not ? not(filter) : filter;
    }
}
