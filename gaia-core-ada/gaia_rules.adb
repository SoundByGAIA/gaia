package body Gaia_Rules with SPARK_Mode => On is

   --  All arithmetic uses a 64-bit intermediate type, so multiplication cannot
   --  overflow (inputs are bounded by Max_Count). The result is clamped to
   --  Integer. gnatprove proves this.

   function Severity_Weight (Kind : Integer) return Integer is
   begin
      case Kind is
         when 4      => return 100;  -- private key / AWS secret
         when 3      => return 60;   -- API token / password
         when 2      => return 30;   -- suspicious high-entropy
         when 1      => return 10;   -- weak / info
         when others => return 1;
      end case;
   end Severity_Weight;

   function Risk_Score (Crit, High, Med, Low : Integer) return Integer is
      Raw : constant Long_Long_Integer :=
        Long_Long_Integer (Crit) * 40 + Long_Long_Integer (High) * 20 +
        Long_Long_Integer (Med) * 8  + Long_Long_Integer (Low) * 2;
   begin
      if Raw > 100 then
         return 100;
      elsif Raw < 0 then
         return 0;
      else
         return Integer (Raw);
      end if;
   end Risk_Score;

   function Engineer_Days_Saved (Crit, High, Med, Low, Files : Integer) return Integer is
      pragma Unreferenced (Low);
      Days : constant Long_Long_Integer :=
        Long_Long_Integer (Crit) * 2 + Long_Long_Integer (High) +
        Long_Long_Integer (Med) / 4 + Long_Long_Integer (Files) / 200;
   begin
      if Days < 0 then
         return 0;
      elsif Days > Long_Long_Integer (Integer'Last) then
         return Integer'Last;
      else
         return Integer (Days);
      end if;
   end Engineer_Days_Saved;

   function Dollars_Saved (Days, Crit : Integer) return Integer is
      Amount : constant Long_Long_Integer :=
        Long_Long_Integer (Days) * 600 + Long_Long_Integer (Crit) * 5000;
   begin
      if Amount < 0 then
         return 0;
      elsif Amount > Long_Long_Integer (Integer'Last) then
         return Integer'Last;
      else
         return Integer (Amount);
      end if;
   end Dollars_Saved;

end Gaia_Rules;
