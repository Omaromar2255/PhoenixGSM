namespace PhoenixGSM.OmniTrace.Rollback;

/// <summary>
/// Interface for any reversible system change.
/// واجهة لأي تغيير في النظام يمكن التراجع عنه
/// </summary>
public interface ISystemChange
{
    string ChangeId { get; }
    string Description { get; }
    DateTimeOffset Timestamp { get; }
    bool Apply();   // Apply the change, return success. تطبيق التغيير
    bool Revert();  // Revert the change, return success. التراجع عن التغيير
    bool IsApplied { get; }
}
