package org.cloudfoundry.identity.uaa.resources;

import java.util.List;

public interface PaginationQueryable<T> {
    List<T> query(String filter, String sortBy, boolean ascending, String zoneId, int offset, int pageSize);

}
