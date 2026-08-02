package com.krawenn.auth.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Id;
import jakarta.persistence.MappedSuperclass;
import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.annotations.UuidGenerator;

/**
 * Base class for entities: a time-ordered UUIDv7 identifier plus audit timestamps.
 *
 * <p>UUIDv7 keeps inserts append-friendly at the index level, unlike random v4 keys.
 * Hibernate assigns the value on persist, which is why {@code equals} treats a
 * not-yet-persisted instance as equal only to itself.
 */
@MappedSuperclass
public abstract class AbstractEntity {

    @Id
    @UuidGenerator(style = UuidGenerator.Style.VERSION_7)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    public UUID getId() {
        return id;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    @Override
    public final boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (other == null || getClass() != other.getClass()) {
            return false;
        }
        UUID otherId = ((AbstractEntity) other).id;
        return id != null && id.equals(otherId);
    }

    @Override
    public final int hashCode() {
        // Stable across the transient -> persistent transition, which a null-safe
        // Objects.hash(id) would not be.
        return getClass().hashCode();
    }
}
