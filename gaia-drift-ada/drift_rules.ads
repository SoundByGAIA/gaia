package Drift_Rules with SPARK_Mode => On is
   --  External-API drift -> financial risk + ROI rules.
   --  SPARK_Mode: absence of run-time errors (overflow/range) is proved with gnatprove.
   Max_Count : constant := 10_000_000;

   --  Risk score (0-100): critical (removed API) / high (deprecated) / medium (changed) / watch.
   function Drift_Risk (Crit, High, Med, Watch : Integer) return Integer
     with Export => True, Convention => C, External_Name => "drift_risk",
          Pre  => Crit in 0 .. Max_Count and High in 0 .. Max_Count
                  and Med in 0 .. Max_Count and Watch in 0 .. Max_Count,
          Post => Drift_Risk'Result in 0 .. 100;

   --  Daily dollars at risk (a broken critical payment API ~ daily business loss).
   function Dollars_At_Risk (Crit, High, Med : Integer) return Integer
     with Export => True, Convention => C, External_Name => "drift_dollars_at_risk",
          Pre  => Crit in 0 .. Max_Count and High in 0 .. Max_Count and Med in 0 .. Max_Count,
          Post => Dollars_At_Risk'Result >= 0;

   --  Estimated fix effort in engineer-days.
   function Fix_Days (Crit, High, Med : Integer) return Integer
     with Export => True, Convention => C, External_Name => "drift_fix_days",
          Pre  => Crit in 0 .. Max_Count and High in 0 .. Max_Count and Med in 0 .. Max_Count,
          Post => Fix_Days'Result >= 0;
end Drift_Rules;
