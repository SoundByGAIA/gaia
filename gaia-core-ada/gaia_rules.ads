package Gaia_Rules with SPARK_Mode => On is
   --  Finding classification, risk score and ROI rules.
   --  SPARK_Mode: absence of run-time errors (overflow/range) is proved with gnatprove.

   --  Counts are bounded so products cannot overflow (proved by SPARK).
   Max_Count : constant := 10_000_000;

   --  Finding kind -> severity weight (0=info..4=critical)
   function Severity_Weight (Kind : Integer) return Integer
     with Export => True, Convention => C, External_Name => "gaia_severity_weight",
          Post => Severity_Weight'Result in 1 .. 100;

   --  Overall risk score (0-100) from critical/high/medium/low counts
   function Risk_Score (Crit, High, Med, Low : Integer) return Integer
     with Export => True, Convention => C, External_Name => "gaia_risk_score",
          Pre  => Crit in 0 .. Max_Count and High in 0 .. Max_Count
                  and Med in 0 .. Max_Count and Low in 0 .. Max_Count,
          Post => Risk_Score'Result in 0 .. 100;

   --  Estimated engineer-days saved (pre-breach catch + manual review)
   function Engineer_Days_Saved (Crit, High, Med, Low, Files : Integer) return Integer
     with Export => True, Convention => C, External_Name => "gaia_engineer_days_saved",
          Pre  => Crit in 0 .. Max_Count and High in 0 .. Max_Count
                  and Med in 0 .. Max_Count and Low in 0 .. Max_Count
                  and Files in 0 .. Max_Count,
          Post => Engineer_Days_Saved'Result >= 0;

   --  Estimated dollars saved (engineer-days x avg cost + breach-risk reduction)
   function Dollars_Saved (Days, Crit : Integer) return Integer
     with Export => True, Convention => C, External_Name => "gaia_dollars_saved",
          Pre  => Days in 0 .. Max_Count and Crit in 0 .. Max_Count,
          Post => Dollars_Saved'Result >= 0;
end Gaia_Rules;
