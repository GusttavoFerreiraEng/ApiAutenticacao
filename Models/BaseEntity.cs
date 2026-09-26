using System;

namespace Models
{
    public abstract class BaseEntity
    {  // Define propriedades comuns para todas as entidades.
        public long Id { get; set; }
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
        public DateTimeOffset? UpdatedAt { get; set; }
    }
}