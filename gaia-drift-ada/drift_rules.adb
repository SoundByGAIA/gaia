package body Drift_Rules with SPARK_Mode => On is
   --  Arithmetic uses a 64-bit intermediate type, so multiplication cannot overflow (inputs bounded by Max_Count).
   --  The result is clamped to Integer. gnatprove proves this.

   function Drift_Risk (Crit, High, Med, Watch : Integer) return Integer is
      R : constant Long_Long_Integer :=
        Long_Long_Integer (Crit) * 45 + Long_Long_Integer (High) * 20 +
        Long_Long_Integer (Med) * 8  + Long_Long_Integer (Watch) * 3;
   begin
      if R > 100 then
         return 100;
      elsif R < 0 then
         return 0;
      else
         return Integer (R);
      end if;
   end Drift_Risk;

   function Dollars_At_Risk (Crit, High, Med : Integer) return Integer is
      --  Critical (removed payment/shipping API) ~$15k/day at risk; high ~$4k; medium ~$800.
      D : constant Long_Long_Integer :=
        Long_Long_Integer (Crit) * 15000 + Long_Long_Integer (High) * 4000 +
        Long_Long_Integer (Med) * 800;
   begin
      if D < 0 then
         return 0;
      elsif D > Long_Long_Integer (Integer'Last) then
         return Integer'Last;
      else
         return Integer (D);
      end if;
   end Dollars_At_Risk;

   function Fix_Days (Crit, High, Med : Integer) return Integer is
      F : constant Long_Long_Integer :=
        Long_Long_Integer (Crit) * 3 + Long_Long_Integer (High) +
        (Long_Long_Integer (Med) + 3) / 4;
   begin
      if F < 0 then
         return 0;
      elsif F > Long_Long_Integer (Integer'Last) then
         return Integer'Last;
      else
         return Integer (F);
      end if;
   end Fix_Days;
end Drift_Rules;
